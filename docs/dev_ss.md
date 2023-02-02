---
layout: default
title: Developers
permalink: /developers/
nav_order: 5
has_children: false
---
This guide will explain how to setup the Secure-Signer development environment.

## Install PreReqs
We assume that the SGX driver and Docker dependencies have been installed following the instructions [here](../installation).


## Install Build Dependencies
Secure-Signer has several build dependencies. Run the following command to install them:
<div class="code-example" markdown="1">
```bash
sudo DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends libcurl4-openssl-dev libssl-dev libprotobuf-dev libfuse-dev autoconf automake make cmake libtool gdb python jq ca-certificates gnupg python3-dev wget python3.8-venv build-essential ocaml 
```
</div>

## Clone Secure-Signer
For the remainder of this guide, we assume the repo is cloned into the home (`~`) directory.
<div class="code-example" markdown="1">
```bash
git clone https://github.com/PufferFinance/secure-signer.git
```
</div>

## Starting the container
### Using `run_secure_signer.sh`
The `run_secure_signer.sh` is a convenience script for working with the development and release Docker containers. Usage:
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ cd secure-signer/    
puffer@Puffer-Dev:~/secure-signer$ ./run_secure_signer.sh -h                                                                    
Run container images secure_signer_image in background.
usage: run_secure_signer.sh [OPTION]...
    -p <Secure-Signer Server port> default 9001.
    -d run in development mode.
    -r run in release mode.
    -a attach to the specified image without running.
    -f force remove existing container.
    -h <usage> usage help
```
</div>

Run the following command to launch and attach to the development container. The script will mount the `~/secure-signer` repo as a volume so any development work done inside the container will persist.
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~/secure-signer$ ./run_secure_signer.sh -d -a
Launching secure_signer_container_dev...
e2439f4ed4e6317c67dd51261b99061a365adb6e05222e9abb064c00ca774972
Attaching to secure_signer_container_dev...
root@Puffer-Dev:~#
```
</div>

Notice the username is now `root`, indicating we are now inside the container. In a different shell we can verify that the container is running:
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~/secure-signer$ docker container ls
CONTAINER ID   IMAGE                              COMMAND   CREATED         STATUS         PORTS     NAMES
e2439f4ed4e6   occlum/occlum:latest-ubuntu20.04   "bash"    2 minutes ago   Up 2 minutes             secure_signer_container_dev
```
</div>


### From the command line
Alternatively, we can launch the container from the commandline. For development we use the `occlum/occlum:latest` container image. The following command will start running a development container with the name `secure_signer_container_dev`. The following command will mount the `~/secure-signer` repo as a volume, but edit this if you cloned `secure-signer` to a different directory.
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~/secure-signer$ docker run -itd --privileged -v ~/secure-signer:/root/secure-signer -v /dev/sgx_enclave:/dev/sgx/enclave --name secure_signer_container_dev -v /dev/sgx_provision:/dev/sgx/provision -v /var/run/aesmd:/var/run/aesmd --network="host" occlum/occlum:latest-ubuntu20.04
f72d93ab0ae04e7ab77b60eb55fe32044e952b2ed3f949518f28591eb877bb12
puffer@Puffer-Dev:~/secure-signer$ docker container ls
CONTAINER ID   IMAGE                              COMMAND   CREATED          STATUS          PORTS     NAMES
f72d93ab0ae0   occlum/occlum:latest-ubuntu20.04   "bash"    45 seconds ago   Up 44 seconds             secure_signer_container_dev
puffer@Puffer-Dev:~/secure-signer$ docker exec -it secure_signer_container_dev bash
root@Puffer-Dev:~#
```
</div>



## Set correct Rust version
Secure-Signer works with rustc version 1.64.0. Run the following commands from inside the container to update your rust toolchain:
<div class="code-example" markdown="1">
```bash
rustup update 1.64.0  
rustup default 1.64.0  
rustup target add x86_64-unknown-linux-musl
```
</div>

### Using `build_secure_signer.sh`
The `build_secure_signer.sh` is a convenience script for building and running Secure-Signer. Usage:
<div class="code-example" markdown="1">
```bash
root@Puffer-Dev:~# cd secure-signer/ 
root@Puffer-Dev:~/secure-signer# ./build_secure_signer.sh -h
Build and containerize Secure-Signer.
usage: build_secure_signer.sh [OPTION]...
    -p <Secure-Signer Server port> default 9001.
    -c clean Cargo then build all
    -b build from cached dependencies
    -x Run Secure-Signer on port set by -p (default 9001) (assumes this script is executed in Docker container).
    -d Build and package the DEVELOPMENT Docker Image
    -r Build and package the RELEASE Docker Image
    -m Measure Secure-Signer's MRENCLAVE and MRSIGNER.
    -h <usage> usage help
```
</div>

## Build the Secure-Signer codebase
The following command will compile the codebase, create an Occlum image, and start running the enclave with the default port `9001`.
<div class="code-example" markdown="1">
```bash
./build_secure_signer.sh -b -x
```
</div>

## Running Tests
Use the following command to run unit tests (from inside the Docker container). Note that the tests access a shared filesystem and should be run sequentially.
<div class="code-example" markdown="1">
```bash
cargo test --features=dev -- --test-threads 1
```
</div>

