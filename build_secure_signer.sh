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
    rm -rf ${enclave_name}
    mkdir -p ${image_path}

    pushd ${enclave_name}
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
    pushd ${image_path}
        echo "MRENCLAVE:"
        occlum print mrenclave
        echo "MRSIGNER:"
        occlum print mrsigner
    popd
}

function run() {
    cd ${image_path} && occlum run /bin/${binary_name} ${ss_port}
}

function package() {
    cd ${image_path} && occlum package ${enclave_name}
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

function dockerize() {
    pushd ${script_dir}
        ./container/build_image.sh \
            -i ./${enclave_name}/${enclave_name}.tar.gz \
            -n secure_signer_image
    echo ${script_dir}

    popd 
}

function usage {
    cat << EOM
Run container images secure_signer_image in background.
usage: $(basename "$0") [OPTION]...
    -p <Secure-Signer Server port> default 9001.
    -c clean Cargo then build all
    -b build cached
    -r Run Secure-Signer on port set by -p (default 9001).
    -d Clean Build -> package -> create Docker Image
    -m Measure MRENCLAVE and MRSIGNER.
    -h <usage> usage help
EOM
    exit 0
}

function process_args {
    while getopts ":pcbrdmh" option; do
        case "${option}" in
            p) ss_port=${OPTARG};;
            c) clean_build;;
            b) build;;
            r) run;;
            d) dockerize;;
            m) measure;;
            h) usage;;
        esac
    done
}
process_args "$@"