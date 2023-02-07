#!/bin/bash
set -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" >/dev/null 2>&1 && pwd )"

export ra_config_name="ra_config.json"
export enclave_name="Secure-Signer"
export image_path="${script_dir}/${enclave_name}"
export binary_name="secure-signer"
export base_image_name="container/Dockerfile_SS.ubuntu20.04"
export image_name="secure_signer"
export registry="pufferfinance"
export tag="latest"
export executable="./target/release/client"
export config="./conf/network_config.json"
export measurement="./Secure-Signer/MRENCLAVE"
export ss_port=9001

# If LOCAL_DEV is not set assume compiling for Occlum
if [ -z "$LOCAL_DEV" ]; then
    cargo_bin="occlum-cargo"
    OPENSSL_DIR="/usr/local/occlum/x86_64-linux-musl/"
else
    cargo_bin="cargo"
    build_flags="--features=dev"
fi

function build_secure_signer()
{

    if [ -z "$LOCAL_DEV" ]; then
        # compiles EPID remote attestation cpp code
        ./build_epid_ra.sh
    fi

    # compile secure-signer
	${cargo_bin} build --release ${build_flags}
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
        occlum print mrenclave > MRENCLAVE
        cat MRENCLAVE
        echo "MRSIGNER:"
        occlum print mrsigner > MRSIGNER
        cat MRSIGNER
    popd > /dev/null
}

function run() {
    pushd ${image_path}
    if [ -z "$LOCAL_DEV" ]; then
        occlum run /bin/${binary_name} ${ss_port}
    else
        cargo run ${build_flags} --bin ${binary_name} ${ss_port}
    fi
    popd
}

function package() {
    pushd ${image_path}
        occlum package ${enclave_name}
    popd
}

function build() {
    build_secure_signer
    if [ -z "$LOCAL_DEV" ]; then
        new_ss_instance
        measure
        package
    fi
}

function clean_build() {
    ${cargo_bin} clean
    build
}

function unit_tests() {
    ${cargo_bin} test --features=dev -- --test-threads 1  
}

# Function to build the Secure Signer container image either in development or release mode
function dockerize() {
    # Change the directory to script_dir
    pushd ${script_dir} > /dev/null
        # Build the container image 
        ./container/build_image.sh \
            -i ./${enclave_name}/${enclave_name}.tar.gz \
            -n ${image_name} \
            -b ${base_image_name} \
            -r ${registry} \
            -g ${tag} \
            -c ${config} \
            -e ${executable} \
            -m ${measurement}
    popd > /dev/null
}

function usage {
    cat << EOM
Build and containerize Secure-Signer.
Run "LOCAL_DEV=true ./build_secure_signer.sh <args>" for local dev compilation without SGX dependencies.
usage: $(basename "$0") [OPTION]...
    -p <Secure-Signer Server port> default 9001.
    -c clean Cargo then build all
    -b build from cached dependencies
    -x Run Secure-Signer on port set by -p (default 9001)
    -d Build and package the Docker Container Image (assumes "occlum package" has been run)
    -m Measure Secure-Signer's MRENCLAVE and MRSIGNER (assumes this is run in SGX env)
    -t Run all unit tests
    -h <usage> usage help
EOM
    exit 0
}


function process_args {
    # Use getopts to process the arguments
    while getopts ":pcbxdmtp:h" option; do
        case "${option}" in
            p) ss_port=${OPTARG};;
            c) clean_build;;
            b) build;;
            x) run;;
            m) measure;;
            d) dockerize;;
            t) unit_tests;;
            h) usage;;
        esac
    done
}

# Call the process_args function to handle the script arguments
process_args "$@"