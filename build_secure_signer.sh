#!/bin/bash
set -e

script_dir="$(dirname $(readlink -f $0))"

export OPENSSL_DIR="/usr/local/occlum/x86_64-linux-musl/"
export RA_CONFIG_NAME="ra_config.json"
export ENCLAVE_NAME="Secure-Signer"
export INSTANCE_PATH="${script_dir}/${ENCLAVE_NAME}"
export BINARY_NAME="secure-signer"
export PORT=9001

function build_secure_signer()
{
  	# compiles EPID remote attestation cpp code
	./build_epid_ra.sh

    # compile secure-signer
    # occlum-cargo clean
	occlum-cargo build --release
}

function new_ss_instance()
{
    rm -rf ${ENCLAVE_NAME}
    mkdir -p ${INSTANCE_PATH}

    pushd ${ENCLAVE_NAME}
    occlum init ${ENCLAVE_NAME}

    # prepare SS content
    copy_bom -f ../conf/secure-signer-rust-config.yaml --root image --include-dir /opt/occlum/etc/template
	cp ../conf/${RA_CONFIG_NAME} ./image/etc/
    cp /etc/resolv.conf ./image/etc
	cp /etc/hosts ./image/etc

    new_json="$(jq '.resource_limits.user_space_size = "128MB" |
                    .resource_limits.kernel_space_heap_size="256MB" |
                    .process.default_heap_size = "32MB" |
                    .resource_limits.max_num_of_threads = 32 |
                    .metadata.debuggable = false' Occlum.json)" && \
    echo "${new_json}" > Occlum.json
    
    # build the image
    occlum build

    # occlum package ${ENCLAVE_NAME}
    popd
}

function get_mr() {
    pushd ${INSTANCE_PATH}
        echo "MRENCLAVE:"
        occlum print mrenclave
        echo "MRSIGNER:"
        occlum print mrsigner
    popd
}

function run() {
    cd ${INSTANCE_PATH} && occlum run /bin/${BINARY_NAME} ${PORT}
}

function package() {
    cd ${INSTANCE_PATH} && occlum package ${ENCLAVE_NAME}
}


build_secure_signer
new_ss_instance
package
get_mr
run