#!/bin/bash
set -e

script_dir="$(dirname $(readlink -f $0))"

export binary_name="secure-signer"
ss_port=9001


# Function to build the Secure Signer container image either in development or release mode
function run_ss() {
    echo "Start Secure-Signer server on port ${ss_port}..."
    docker run -itd --network host \
        -v ~/secure-signer:/root/secure-signer \
        -v /var/run/aesmd:/var/run/aesmd \
        --device /dev/sgx/enclave --device /dev/sgx/provision \
        --name ${container_name} \
        ${registry}/${image_name}:${tag} \
        occlum run /bin/${binary_name} ${ss_port} &
}

# Function to build the Secure Signer container image either in development or release mode
function attach_image() {
    echo "Launching ${container_name}..."
    docker run -itd --network host \
        -v ~/secure-signer:/root/secure-signer \
        -v /var/run/aesmd:/var/run/aesmd \
        --device /dev/sgx/enclave --device /dev/sgx/provision \
        --name ${container_name} \
        ${registry}/${image_name}:${tag}
    echo "Attaching to ${container_name}..."
    docker exec -it ${container_name} bash
}

function clean_existing_container() {
    container_id=$(docker ps --filter "name=^/${container_name}" --format '{{.Names}}')
    if [ -n "${container_id}" ] && [ "${remove_old}" ]; then
        docker container stop ${container_name}
        docker container rm ${container_name}
        echo 'Removed old container'
    fi
}

function usage {
    cat << EOM
Run container images secure_signer_image in background.
usage: $(basename "$0") [OPTION]...
    -p <Secure-Signer Server port> default 9001.
    -d run in development mode.
    -r run in release mode.
    -a attach to the specified image without running.
    -f force remove existing container.
    -h <usage> usage help
EOM
    exit 0
}

function process_args {
    while getopts ":pdarf:h" option; do
        case "${option}" in
            p) ss_port=${OPTARG};;
            d) development=true;;
            r) release=true;;
            a) attach=true;;
            f) remove_old=true;;
            h) usage;;
        esac
    done
}

process_args "$@"

if [ $release ]; then
    container_name="secure_signer_container"
    image_name="secure_signer"
    registry="pufferfinance"
    tag="latest"
elif [ $development ]; then
    container_name="secure_signer_container_dev"
    image_name="occlum"
    registry="occlum"
    tag="latest-ubuntu20.04"
else
    echo "Error: Must specify either -r (release) or -d (development) flag"
    exit 1
fi

if [ $remove_old ]; then
    clean_existing_container
fi

if [ $attach ]; then
    attach_image
else
    run_ss
fi
