#!/bin/bash
set -e

script_dir=$(dirname $(realpath $0))
volume_mount_1="$script_dir:/root/"
volume_mount_2="/var/run/aesmd:/var/run/aesmd"
device_1="/dev/sgx_enclave"
device_2="/dev/sgx_provision"

# Allow us to talk via localhost
network_name="host"

# Initialize default values
container_prefix=""
ss_port=9001

# Function to run the container
function run_container() {
    echo "Start ${container_prefix}-server on port ${ss_port}..."
    docker run -itd --privileged \
        -v $volume_mount_1${container_prefix} \
        -v $volume_mount_2 \
        --device $device_1 \
        --device $device_2 \
        --network $network_name \
        --name ${container_name} \
        ${registry}/${image_name}:${tag}

    # Run the startup command
    docker exec -it $container_name bash -c "$startup_command"
}

# Function to attach to an existing container
function attach_image() {
    if [ "$(docker ps -aq -f name=$container_name)" ]; then
        echo "Attaching to ${container_name}..."
        docker exec -it ${container_name} bash
    else
        echo "${container_name} not found, launching now..."
        run_container
        docker exec -it ${container_name} bash
    fi
}

function clean_existing_container() {
    if [ "$(docker ps -aq -f name=$container_name)" ]; then
        echo "Removing ${container_name}..."
        docker stop $container_name && docker rm $container_name
    fi
}

function usage {
    cat << EOM
Run container images in background.
usage: $(basename "$0") [OPTION]...
    -p <Server port> default 9001.
    -g set guardian enclave.
    -v set validator enclave.
    -s set secure-signer enclave.
    -d run in development mode.
    -r run in release mode.
    -a attach to the specified image without running.
    -f force remove existing container.
    -h <usage> usage help
EOM
    exit 0
}

function process_args {
    while getopts ":pgvsdarfh" option; do
        case "${option}" in
            p) ss_port=${OPTARG};;
            g) container_prefix="guardian";;
            v) container_prefix="validator";;
            s) container_prefix="secure-signer";;
            d) development=true;;
            r) release=true;;
            a) attach=true;;
            f) remove_old=true;;
            h) usage;;
        esac
    done
}

process_args "$@"

if [ -z "$container_prefix" ]; then
    echo "Error: Must specify one of -g (guardian), -v (validator), or -s (secure-signer)"
    exit 1
fi

if [ $release ]; then
    container_name="${container_prefix}_container"
    image_name="${container_prefix}"
    registry="pufferfinance"
    tag="latest"
    startup_command="occlum run /bin/${container_prefix} ${ss_port} &"
elif [ $development ]; then
    container_name="${container_prefix}_container_dev"
    image_name="occlum"
    registry="occlum"
    tag="0.29.1-ubuntu20.04"
    startup_command="rustup update 1.71.0 && rustup default 1.71.0 && rustup target add x86_64-unknown-linux-musl"
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
    run_container
fi
