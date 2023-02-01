#!/bin/bash
set -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" >/dev/null 2>&1 && pwd )"

export OPENSSL_DIR="/usr/local/occlum/x86_64-linux-musl/"
export ra_config_name="ra_config.json"
export enclave_name="Secure-Signer"
export image_path="${script_dir}/${enclave_name}"
export binary_name="secure-signer"
ss_port=9001

function build_secure_signer()
{
  	# compiles EPID remote attestation cpp code
	./build_epid_ra.sh

    # compile secure-signer
	occlum-cargo build --release
}

function new_ss_instance()
{
    rm -rf ${image_path}
    mkdir -p ${image_path}

    pushd ${image_path}
        occlum init ${enclave_name}

        # prepare SS content
        copy_bom -f ../conf/secure-signer-rust-config.yaml --root image --include-dir /opt/occlum/etc/template
        cp ../conf/${ra_config_name} ./image/etc/
        cp /etc/resolv.conf ./image/etc
        cp /etc/hosts ./image/etc

        new_json="$(jq '.resource_limits.user_space_size = "128MB" |
                        .resource_limits.kernel_space_heap_size="256MB" |
                        .process.default_heap_size = "32MB" |
                        .resource_limits.max_num_of_threads = 32 |
                        .metadata.debuggable = false' Occlum.json)" && \
        echo "${new_json}" > Occlum.json
        
        occlum build 
    popd
}

function measure() {
    pushd ${image_path} > /dev/null
        echo "MRENCLAVE:"
        occlum print mrenclave
        echo "MRSIGNER:"
        occlum print mrsigner
    popd > /dev/null
}

function run() {
    pushd ${image_path}
        occlum run /bin/${binary_name} ${ss_port}
    popd
}

function package() {
    pushd ${image_path}
        occlum package ${enclave_name}
    popd
}

function build() {
    build_secure_signer
    new_ss_instance
    measure
    package
}

function clean_build() {
    occlum-cargo clean
    build
}

# Function to build the Secure Signer container image either in development or release mode
function dockerize() {
    # Change the directory to script_dir
    pushd ${script_dir}
        if [ $release ]; then
            base_image_name="container/Dockerfile_SS.ubuntu20.04"
            image_name="secure_signer_image"
        elif [ $development ]; then
            base_image_name="container/Dockerfile_SS_dev.ubuntu20.04"
            image_name="secure_signer_dev_image"
        else
            echo "Error: Must specify either --release or --development flag"
            exit 1
        fi

        # Build the container image 
        ./container/build_image.sh \
            -i ./${enclave_name}/${enclave_name}.tar.gz \
            -n ${image_name} \
            -b ${base_image_name}
    popd
}

function usage {
    cat << EOM
Build and containerize Secure-Signer.
usage: $(basename "$0") [OPTION]...
    -p <Secure-Signer Server port> default 9001.
    -c clean Cargo then build all
    -b build from cached dependencies
    -x Run Secure-Signer on port set by -p (default 9001) (assumes this script is executed in Docker container).
    -d Build and package the DEVELOPMENT Docker Image
    -r Build and package the RELEASE Docker Image
    -m Measure Secure-Signer's MRENCLAVE and MRSIGNER.
    -h <usage> usage help
EOM
    exit 0
}


function process_args {
    # Use getopts to process the arguments
    while getopts ":pcbxrdmp:h" option; do
        case "${option}" in
            p) ss_port=${OPTARG};;
            c) clean_build;;
            b) build;;
            x) run;;
            m) measure;;
            d) development=true; dockerize;;
            r) release=true; dockerize;;
            h) usage;;
        esac
    done
}

# Call the process_args function to handle the script arguments
process_args "$@"