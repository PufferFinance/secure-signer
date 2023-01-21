#!/bin/bash
set -e

script_dir="$(dirname $(readlink -f $0))"

export binary_name="secure-signer"
container_name="secure_signer_container_dev"
ss_port=9001
registry="puffer"
tag="latest"

function usage {
    cat << EOM
Run container images secure_signer_image in background.
usage: $(basename "$0") [OPTION]...
    -p <Secure-Signer Server port> default 9001.
    -h <usage> usage help
EOM
    exit 0
}

function process_args {
    while getopts ":p:h" option; do
        case "${option}" in
            p) ss_port=${OPTARG};;
            h) usage;;
        esac
    done
}

process_args "$@"

# clean existing container
docker container rm ${container_name}

echo "Start Secure-Signer server in backgound ..."
docker run -itd --network host \
        -v ~/secure-signer:/root/secure-signer \
        -v /var/run/aesmd:/var/run/aesmd \
        --device /dev/sgx/enclave --device /dev/sgx/provision \
        --name ${container_name} \
        ${registry}/secure_signer_image:${tag} #\
        # occlum run /bin/${binary_name} ${ss_port} &

docker ps