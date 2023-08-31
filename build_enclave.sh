#!/bin/bash
set -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" >/dev/null 2>&1 && pwd )"


export ra_config_name="ra_config.json"
export image_path="${script_dir}/${enclave_name}"
export base_image_name="container/Dockerfile_SS.ubuntu20.04"
export registry="pufferfinance"
export tag="latest"
export executable="./target/release/client"
export config="./conf/network_config.json"
export measurement="./${enclave_name}/MRENCLAVE"
export genesis_fork_version="0x00001020"

# If LOCAL_DEV is not set assume compiling for Occlum
if [ -z "$LOCAL_DEV" ]; then
    cargo_bin="occlum-cargo"
    export OPENSSL_DIR="/usr/local/occlum/x86_64-linux-musl/"
    build_flags="--release --features=sgx"
else
    cargo_bin="cargo"
fi

function build_secure_signer()
{

    if [ -z "$LOCAL_DEV" ]; then
        # compiles EPID remote attestation cpp code
        ./build_epid_ra.sh
    fi

    # compile secure-signer
	${cargo_bin} build ${build_flags} --bin secure-signer
}

function build_guardian()
{

    if [ -z "$LOCAL_DEV" ]; then
        # compiles EPID remote attestation cpp code
        ./build_epid_ra.sh
    fi

    # compile secure-signer
	${cargo_bin} build ${build_flags} --bin guardian
}

function new_instance()
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

function run_secure_signer() {
    pushd ${image_path}
    if [ -z "$LOCAL_DEV" ]; then
        occlum run /bin/${binary_name} ${port} ${genesis_fork_version} 
    else
        cargo run ${build_flags} --bin ${binary_name} ${port} ${genesis_fork_version}
    fi
    popd
}

function run_guardian() {
    pushd ${image_path}
    if [ -z "$LOCAL_DEV" ]; then
        occlum run /bin/${binary_name} ${port} ${genesis_fork_version} 
    else
        cargo run ${build_flags} --bin ${binary_name} ${port} ${genesis_fork_version}
    fi
    popd
}

function run_validator() {
    pushd ${image_path}
    if [ -z "$LOCAL_DEV" ]; then
        occlum run /bin/${binary_name} ${port} ${genesis_fork_version} 
    else
        cargo run ${build_flags} --bin ${binary_name} ${port} ${genesis_fork_version}
    fi
    popd
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

function build() {
    build_secure_signer
    if [ -z "$LOCAL_DEV" ]; then
        new_instance
        measure
        package
    fi
}

function build_client() {
	${cargo_bin} build --release --bin client --features=clap
}


function clean_build() {
    ${cargo_bin} clean
    build
}

function unit_tests() {
    ${cargo_bin} test -- --test-threads 1  
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
    -s Run Secure-Signer on port set by -p (default 9001)
    -g Run Guardian on port set by -p (default 9002)
    -d Build and package the Docker Container Image (assumes "occlum package" has been run)
    -m Measure Secure-Signer's MRENCLAVE and MRSIGNER (assumes this is run in SGX env)
    -t Run all unit tests
    -a Compile client app
    -h <usage> usage help
EOM
    exit 0
}




function process_args {
    # Use getopts to process the arguments
    while getopts ":pcbsgvdamtp:h" option; do
        echo $option
        case "${option}" in
            s)
                export enclave_name="Secure-Signer"
                export binary_name="secure-signer"
                export image_name="secure_signer"
                export port=9001
                run_secure_signer;;
            g) 
                export enclave_name="Guardian"
                export binary_name="guardian"
                export image_name="guardian"
                export port=9002
                run_guardian;;
            v) 
                export enclave_name="Validator"
                export binary_name="validator"
                export image_name="validator"
                export port=9003
                run_validator;;
            p) port=${OPTARG};;
            c) clean_build;;
            b) build;;
            m) measure;;
            d) dockerize;;
            t) unit_tests;;
            a) build_client;;
            h) usage;;
        esac
    done

    if [ $OPTIND -eq 1 ]; then usage; fi
}


# Call the process_args function to handle the script arguments
process_args "$@"
