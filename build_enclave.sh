#!/bin/bash
set -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" >/dev/null 2>&1 && pwd )"

ra_config_name="ra_config.json"
base_image_name="container/Dockerfile_SS.ubuntu20.04"
registry="pufferfinance"
tag="latest"
executable="./target/release/client"
config="./conf/network_config.json"
genesis_fork_version="0x00001020"
build_type=""


if [ -z "$LOCAL_DEV" ]; then
    cargo_bin="occlum-cargo"
    OPENSSL_DIR="/usr/local/occlum/x86_64-linux-musl/"
    build_flags="--release --features=sgx"
else
    cargo_bin="cargo"
fi

function build_image() {
    local enclave_name=$1
    local binary_name=$2
    local image_name=$3
    local image_path=$4

    build_component ${enclave_name} ${binary_name} ${build_flags}
    new_instance ${image_path} ${enclave_name}
    measure ${image_path}
    package ${image_path} ${enclave_name}
}

function package() {
    pushd ${image_path}
        occlum package ${enclave_name}
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

function build_component() {
    local enclave_name=$1
    local binary_name=$2
    local build_flags=$3

    if [ -z "$LOCAL_DEV" ]; then
        ./build_epid_ra.sh
    fi

    OPENSSL_DIR=$OPENSSL_DIR ${cargo_bin} build ${build_flags} -F sgx --bin ${binary_name}
}

function new_instance() {
    local image_path=$1
    local enclave_name=$2

    rm -rf ${image_path}
    mkdir -p ${image_path}

    pushd ${image_path}
        occlum init ${enclave_name}

        # prepare SS content
        copy_bom -f ../conf/${build_type}-rust-config.yaml --root image --include-dir /opt/occlum/etc/template
        cp ../conf/${ra_config_name} ./image/etc/
        cp /etc/resolv.conf ./image/etc
        cp /etc/hosts ./image/etc

        # TODO: play with those values -> get it to work, then minimize 
        new_json="$(jq '.resource_limits.user_space_size = "1024MB" |
                        .resource_limits.kernel_space_heap_size="512MB" |
                        .process.default_heap_size = "512MB" |
                        .resource_limits.max_num_of_threads = 32 |
                        .env.default = ["OCCLUM=yes", "RUST_LOG=info"] |
                        .metadata.debuggable = false' Occlum.json)" && \
        echo "${new_json}" > Occlum.json
        
        occlum build 
    popd
}

function run_component() {
    local image_path=$1
    local binary_name=$2
    local port=$3
    local genesis_fork_version=$4

    pushd ${image_path}
        if [ -z "$LOCAL_DEV" ]; then
            # TODO: find a flag to specify tracing/ possibly LOG_LEVEL=DEBUG
            occlum run /bin/${binary_name} ${port} ${genesis_fork_version}
        else
            cargo run ${build_flags} --bin ${binary_name} ${port} ${genesis_fork_version}
        fi
    popd
}

function usage {
    
echo "Build and containerize enclave."
    if [ -z "$LOCAL_DEV" ]; then
     echo "LOCAL_DEV=true ./build_enclave.sh <args>" for local dev compilation without SGX dependencies.
    else 
     echo "Running with LOCAL_DEV=true, omitting SGX dependencies"
    fi
    
    cat << EOM
    usage: $(basename "$0") [OPTION]...
    -p <Secure-Signer Server port> default 9001.
    -c clean Cargo then build all
    -b build from cached dependencies
    -s Use Secure-Signer service (default port 9001)
    -g Use Guardian service (default port 9002)
    -x Run service on port set by -p (or default to the service)
    -d Build and package the Docker Container Image (assumes "occlum package" has been run)
    -m Measure Secure-Signer's MRENCLAVE and MRSIGNER (assumes this is run in SGX env)
    -t Run all unit tests
    -a Compile client app
    -h <usage> usage help
EOM
    exit 0
}

function unit_tests() {
    OPENSSL_DIR=$OPENSSL_DIR ${cargo_bin} test -F sgx -- --test-threads 1  
}


function process_args() {
    while getopts ":pcbsgvxdgtamp:h" option; do
        case "${option}" in
            s)
                build_type="secure-signer"
                port=9001
                ;;
            g)
                build_type="guardian"
                port=9002
                ;;
            v)
                build_type="validator"
                port=9003
                ;;
            p) 
                port=${OPTARG}
                ;;

            t) 
                unit_tests
                ;;
            b)
                case "${build_type}" in
                    "secure-signer")
                        build_image "Secure-Signer" "secure-signer" "secure_signer" "${script_dir}/Secure-Signer"
                        ;;
                    "guardian")
                        build_image "Guardian" "guardian" "guardian" "${script_dir}/Guardian"
                        ;;
                    "validator")
                        build_image "Validator" "validator" "validator" "${script_dir}/Validator"
                        ;;
                    *)
                        echo "Error: No valid build type specified. Use -v, -g, or -s first."
                        exit 1
                        ;;
                esac
                ;;
            x)
                case "${build_type}" in
                    "secure-signer")
                        run_component "${script_dir}/Secure-Signer" "secure-signer" ${port} ${genesis_fork_version}
                        ;;
                    "guardian")
                        run_component "${script_dir}/Guardian" "guardian" ${port} ${genesis_fork_version}
                        ;;
                    "validator")
                        run_component "${script_dir}/Validator" "validator" ${port} ${genesis_fork_version}
                        ;;
                    *)
                        echo "Error: No valid run type specified. Use -v, -g, or -s first."
                        exit 1
                        ;;
                esac
                ;;
            h) 
                usage
                ;;
            # ... other options
        esac
    done

    if [ $OPTIND -eq 1 ]; then usage; fi
}

process_args "$@"