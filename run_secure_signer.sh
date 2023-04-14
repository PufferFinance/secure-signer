#!/bin/bash
set -e

script_dir=$(dirname $(realpath $0))
volume_mount_1="$script_dir:/root/secure-signer"
volume_mount_2="/var/run/aesmd:/var/run/aesmd"
device_1="/dev/sgx_enclave"
device_2="/dev/sgx_provision"

# Allow us to talk to Secure-Signer via localhost 
network_name="host"

export binary_name="secure-signer"
ss_port=9001


# Function to run the Secure Signer container image either in development or release mode
function run_ss() {
    echo "Start Secure-Signer server on port ${ss_port}..."
    docker run -itd --privileged \
        -v $volume_mount_1 \
        -v $volume_mount_2 \
        --device $device_1 \
        --device $device_2 \
        --network $network_name \
        --name ${container_name} \
        ${registry}/${image_name}:${tag} 

        # Run the startup command
        docker exec -it $container_name bash -c "$startup_command"
}

# Function to attach to an existing Secure Signer container image either in development or release mode
function attach_image() {
    if [ "$(docker ps -aq -f name=$container_name)" ]; then
        echo "Attaching to ${container_name}..."
        docker exec -it ${container_name} bash
    else
        echo "${container_name} not found, launching now..."
        run_ss
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
    while getopts ":pdarfh" option; do
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
    startup_command="occlum run /bin/${binary_name} ${ss_port} &"
elif [ $development ]; then
    container_name="secure_signer_container_dev"
    image_name="occlum"
    registry="occlum"
    tag="0.29.1-ubuntu20.04"
    startup_command="rustup update 1.64.0 && rustup default 1.64.0 && rustup target add x86_64-unknown-linux-musl"
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
