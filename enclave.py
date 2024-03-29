#!/usr/bin/env python3
import os
import subprocess
import argparse
import json

OPENSSL_DIR = "/usr/local/occlum/x86_64-linux-musl/"
BASE_IMAGE_PATH = "container/Dockerfile_SS.ubuntu20.04"
DOCKER_REGISTRY = "pufferfinance"
NETWORK_CONFIG = "./conf/ephemery_network_config.json" # todo holesky

def build_enclave(enclave_name, binary_name, enclave_path):
    compile_rust(binary_name, build_flags)
    new_instance(enclave_name, enclave_path)
    measure(enclave_path)
    if package_enclave:
        package(enclave_name, enclave_path)

def package(enclave_name, enclave_path):
    os.chdir(enclave_path)
    subprocess.run(["occlum", "package", enclave_name])

def measure(enclave_path):
    os.chdir(enclave_path)
    with open("MRENCLAVE", "w") as mrenclave_file:
        subprocess.run(["occlum", "print", "mrenclave"], stdout=mrenclave_file)
    with open("MRSIGNER", "w") as mrsigner_file:
        subprocess.run(["occlum", "print", "mrsigner"], stdout=mrsigner_file)
    print("MRENCLAVE: ")
    subprocess.run(["cat", f"{enclave_path}/MRENCLAVE"])
    print("MRSIGNER: ")
    subprocess.run(["cat", f"{enclave_path}/MRSIGNER"])

def compile_rust(binary_name, build_flags):
    if using_enclave:
        subprocess.run(["./build_epid_ra.sh"])
        os.environ["OPENSSL_DIR"] = OPENSSL_DIR
    cmd = [cargo_bin, "build", "--bin", binary_name]
    cmd.extend(build_flags)
    subprocess.run(cmd)

def update_occlum_json(enclave_path):
    with open(f"{enclave_path}/Occlum.json", "r") as occlum_config_file:
        c = json.load(occlum_config_file)
        c["resource_limits"]["user_space_size"] = "1024MB"
        c["resource_limits"]["kernel_space_heap_size"] = "512MB"
        c["process"]["default_heap_size"] = "512MB"
        c["env"]["default"] = ["OCCLUM=yes", "RUST_LOG=info"]
        c["metadata"]["debuggable"] = False
    with open(f"{enclave_path}/Occlum.json", "w") as occlum_config_file:
        occlum_config_file.write(json.dumps(c))

def new_instance(enclave_name, enclave_path):
    if os.path.exists(enclave_path):
        subprocess.run(["rm", "-rf", enclave_path])
    os.makedirs(enclave_path)
    os.chdir(enclave_path)
    subprocess.run(["occlum", "init", enclave_name])
    subprocess.run(["copy_bom", "-f", f"../conf/{build_type}-rust-config.yaml", "--root", "image", "--include-dir", "/opt/occlum/etc/template"])
    subprocess.run(["cp", f"../conf/ra_config.json", "./image/etc/"])
    subprocess.run(["cp", "/etc/resolv.conf", "./image/etc"])
    subprocess.run(["cp", "/etc/hosts", "./image/etc"])
    update_occlum_json(enclave_path)
    subprocess.run(["occlum", "build"])

def run_enclave(binary_name, enclave_path, port, fork_version):
    os.chdir(enclave_path)
    if using_enclave:
        subprocess.run(["occlum", "run", f"/bin/{binary_name}", str(port), fork_version])
    else:
        subprocess.run([cargo_bin, "run", "--bin", binary_name, str(port), fork_version])

def unit_tests():
    if using_enclave:
        os.environ["OPENSSL_DIR"] = OPENSSL_DIR
    os.environ["SECURE_SIGNER_PORT"] = str(port)
    subprocess.run([cargo_bin, "test", "--", "--test-threads", "1"])

def read_fork_version(path):
    try:
        with open(path, 'r') as f:
            c = json.load(f) 
            return c['fork_info']['fork']['current_version']
    except:
        exit(f"Error loading config file: '{path}'")

def dockerize(image_name, enclave_name, tag):
    enclave_zip = f"./{enclave_name}/{enclave_name}.tar.gz"
    measurement = f"./{enclave_name}/MRENCLAVE"
    cmd = ["./container/build_image.sh",
            "-i", enclave_zip,
            "-n", image_name,
            "-b", BASE_IMAGE_PATH,
            "-r", DOCKER_REGISTRY,
            "-g", tag,
            "-c", NETWORK_CONFIG,
            "-m", measurement]
    subprocess.run(cmd)

def process_args():
    parser = argparse.ArgumentParser(description="Build and containerize enclave.")
    parser.add_argument("-p", "--port", type=int, default=9001, help="Enclave port (default: 9001)")
    parser.add_argument("-e", "--enclave", action="store_true", help="Build using occlum-cargo. If unset, builds and runs without SGX.")
    parser.add_argument("-s", "--secure-signer", action="store_true", help="Use Secure-Signer enclave")
    parser.add_argument("-g", "--guardian", action="store_true", help="Use Guardian enclave")
    parser.add_argument("-v", "--validator", action="store_true", help="Use Validator enclave")
    parser.add_argument("-b", "--build", action="store_true", help="Build from cached dependencies")
    parser.add_argument("-x", "--run", action="store_true", help="Run service on specified port or default")
    parser.add_argument("-u", "--unit-tests", action="store_true", help="Run unit tests")
    parser.add_argument("-c", "--config", default="./conf/ephemery_network_config.json", help="Network config JSON")
    parser.add_argument("-m", "--measure", action="store_true", help="Print the specified enclave's measurements")
    parser.add_argument("-o", "--output-package", action="store_true", help="Package the Occlum image for Dockerization")
    parser.add_argument("-d", "--dockerize", action="store_true", help="Dockerize a packaged Occlum image")
    parser.add_argument("-t", "--tag", default="latest", help="Tag for the Docker image")
    args = parser.parse_args()

    # global vars
    global port, build_type, cargo_bin, using_enclave, build_flags, network_config, package_enclave
    port = args.port
    network_config = args.config
    package_enclave = args.output_package

    # Read fork version from network config
    fork_version = read_fork_version(network_config)

    # Build type
    using_enclave = args.enclave
    if using_enclave:
        cargo_bin = "occlum-cargo" 
        build_flags = ["--release", "-F", "sgx"]
    else:
        cargo_bin = "cargo" 
        build_flags = ""

    # Binary type
    if args.secure_signer:
        build_type = "secure-signer"
    elif args.guardian:
        build_type = "guardian"
    elif args.validator:
        build_type = "validator"
    else:
        exit("Error: No valid build type specified. Use -v, -g, or -s first.")
    
    # Measure the enclave
    if args.measure:
        if build_type == "secure-signer":
            measure(f"{script_dir}/Secure-Signer")
        elif build_type == "guardian":
            measure(f"{script_dir}/Guardian")
        elif build_type == "validator":
            measure(f"{script_dir}/Validator")
        else:
            exit("Error: No valid build type specified. Use -v, -g, or -s first.")

    # Build the enclave
    if args.build:
        if build_type == "secure-signer":
            build_enclave("Secure-Signer", "secure-signer", f"{script_dir}/Secure-Signer")
        elif build_type == "guardian":
            build_enclave("Guardian", "guardian", f"{script_dir}/Guardian")
        elif build_type == "validator":
            build_enclave("Validator", "validator", f"{script_dir}/Validator")
        else:
            exit("Error: No valid build type specified. Use -v, -g, or -s first.")

    # Run the enclave
    if args.run:
        if build_type == "secure-signer":
            run_enclave("secure-signer", f"{script_dir}/Secure-Signer", port, fork_version)
        elif build_type == "guardian":
            run_enclave("guardian", f"{script_dir}/Guardian", port, fork_version)
        elif build_type == "validator":
            run_enclave("validator", f"{script_dir}/Validator", port, fork_version)
        else:
            exit("Error: No valid run type specified. Use -v, -g, or -s first.")
    
    if args.unit_tests:
        unit_tests()

    if args.dockerize:
        if build_type == "secure-signer":
            dockerize("secure_signer", "Secure-Signer", args.tag)
        elif build_type == "guardian":
            dockerize("guardian_enclave", "Guardian", args.tag)
        elif build_type == "validator":
            dockerize("validator_enclave", "Validator", args.tag)
        else:
            exit("Error: No valid type specified. Use -v, -g, or -s first.")
    
if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    process_args()
