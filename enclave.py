#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse

OPENSSL_DIR = "/usr/local/occlum/x86_64-linux-musl/"

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

def new_instance(enclave_name, enclave_path):
    if os.path.exists(enclave_path):
        subprocess.run(["rm", "-rf", enclave_path])
    os.makedirs(enclave_path)
    os.chdir(enclave_path)
    subprocess.run(["occlum", "init", enclave_name])
    subprocess.run(["copy_bom", "-f", f"../conf/{build_type}-rust-config.yaml", "--root", "image", "--include-dir", "/opt/occlum/etc/template"])
    subprocess.run(["cp", f"../conf/{ra_network_config_name}", "./image/etc/"])
    subprocess.run(["cp", "/etc/resolv.conf", "./image/etc"])
    subprocess.run(["cp", "/etc/hosts", "./image/etc"])
    new_json = subprocess.check_output(["jq", '.resource_limits.user_space_size = "1024MB" | .resource_limits.kernel_space_heap_size="512MB" | .process.default_heap_size = "512MB" | .resource_limits.max_num_of_threads = 32 | .env.default = ["OCCLUM=yes", "RUST_LOG=info"] | .metadata.debuggable = false', "Occlum.json"]).decode("utf-8")
    with open("Occlum.json", "w") as occlum_json_file:
        occlum_json_file.write(new_json)
    subprocess.run(["occlum", "build"])

def run_enclave(binary_name, enclave_path, port, fork_version):
    os.chdir(enclave_path)
    if using_enclave:
        subprocess.run(["occlum", "run", f"/bin/{binary_name}", str(port), fork_version])
    else:
        subprocess.run([cargo_bin, "run", "--bin", binary_name, str(port), fork_version])

def unit_tests():
    os.environ["OPENSSL_DIR"] = OPENSSL_DIR
    subprocess.run([cargo_bin, "test", "-F", "sgx", "--", "--test-threads", "1"])

def process_args():
    parser = argparse.ArgumentParser(description="Build and containerize enclave.")
    parser.add_argument("-p", "--port", type=int, default=9001, help="Enclave port (default: 9001)")
    parser.add_argument("-e", "--enclave", action="store_true", help="Build using Occlum")
    parser.add_argument("-s", "--secure-signer", action="store_true", help="Use Secure-Signer enclave")
    parser.add_argument("-g", "--guardian", action="store_true", help="Use Guardian enclave")
    parser.add_argument("-v", "--validator", action="store_true", help="Use Validator enclave")
    parser.add_argument("-b", "--build", action="store_true", help="Build from cached dependencies")
    parser.add_argument("-x", "--run", action="store_true", help="Run service on specified port or default")
    parser.add_argument("-t", "--unit-tests", action="store_true", help="Run unit tests")
    parser.add_argument("-n", "--network", choices=["ephemery", "holesky", "mainnet"], default="ephemery", help="Network type (default: ephemery)")
    parser.add_argument("-f", "--fork-version", default="0x00001020", help="Beacon chain fork version")
    parser.add_argument("-m", "--measure", action="store_true", help="Measure")
    parser.add_argument("-o", "--output-package", action="store_true", help="Package the Occlum image for Dockerization")
    args = parser.parse_args()

    # global vars
    global port, build_type, cargo_bin, using_enclave, build_flags, ra_network_config_name, package_enclave, fork_version
    port = args.port
    ra_network_config_name = f"{args.network}_config.json"
    package_enclave = args.output_package

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
            run_enclave("secure-signer", f"{script_dir}/Secure-Signer", port, args.fork_version)
        elif build_type == "guardian":
            run_enclave("guardian", f"{script_dir}/Guardian", port, args.fork_version)
        elif build_type == "validator":
            run_enclave("validator", f"{script_dir}/Validator", port, args.fork_version)
        else:
            exit("Error: No valid run type specified. Use -v, -g, or -s first.")
    
    # if args.unit_tests:
    #     unit_tests()
    
if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    process_args()
