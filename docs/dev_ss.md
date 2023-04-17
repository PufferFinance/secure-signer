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

Run the following command to launch, attach to the development container, and install the correct Rust version. The script will mount the `~/secure-signer` repo as a volume so any development work done inside the container will persist. 
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~/secure-signer$ ./run_secure_signer.sh -d -a                                                                                                                                                 
secure_signer_container_dev not found, launching now...                                                                                                                                                         
Start Secure-Signer server on port 9001...                                                                                                                                                                      
Unable to find image 'occlum/occlum:0.29.1-ubuntu20.04' locally                                                                                                                                                 
0.29.1-ubuntu20.04: Pulling from occlum/occlum                                                                                                                                                                  
fb0b3276a519: Pull complete                                                                                                                                                                                     
d99b42c9728d: Pull complete                                                                                                                                                                                     
74b74e144ba8: Pull complete                                                                                                                                                                                     
e966edf39081: Pull complete                                                                                                                                                                                     
0494b33f9566: Pull complete                                                                                                                                                                                     
4f4fb700ef54: Pull complete                                                                                                                                                                                     
9e819f8f491e: Pull complete                                                                                                                                                                                     
77da17ee521a: Pull complete                                                                                                                                                                                     
4287aaf1a461: Pull complete                                                                                                                                                                                     
045d8386501c: Pull complete                                                                                                                                                                                     
2c050312405e: Pull complete                                                                                                                                                                                     
9ddebcb08677: Pull complete                                                                                                                                                                                     
5fe71afa18d3: Pull complete                                                                                                                                                                                     
b0dde9b3e61d: Pull complete                                                                                                                                                                                     
d2fa00b1a4fd: Pull complete                                                                                                                                                                                     
3b267634335f: Pull complete 
785554322247: Pull complete 
1a33b2bf8917: Pull complete 
4e75289cdfaa: Pull complete 
0357ef5f921c: Pull complete 
ac2932fe67d2: Pull complete 
802f60431b8d: Pull complete 
2c649add70af: Pull complete 
Digest: sha256:de5388e0609d15a4d7797083d69b11d8dcc364c4bc3b9f897922b5e74363cff6                                                                                                                                 
Status: Downloaded newer image for occlum/occlum:0.29.1-ubuntu20.04                                                                                                                                             
2e19c8fc0b246105909a405be6408377644adc5fd73df1dbe6293b8f8d43076e                                                                                                                                                
info: syncing channel updates for '1.64.0-x86_64-unknown-linux-gnu'                                                                                                                                             
warning: Signature verification failed for 'https://static.rust-lang.org/dist/channel-rust-1.64.0.toml'                                                                                                         
info: latest update on 2022-09-22, rust version 1.64.0 (a55dd71d5 2022-09-19)                                                                                                                                   
info: downloading component 'cargo'                                                                                                                                                                             
info: downloading component 'clippy'                                                                                                                                                                            
info: downloading component 'rust-docs'                                                                                                                                                                         
info: downloading component 'rust-std'                                                                                                                                                                          
info: downloading component 'rustc'                                                                                                                                                                             
info: downloading component 'rustfmt'                                                                                                                                                                           
info: installing component 'cargo'                                                                                                                                                                              
info: installing component 'clippy'                                                                                                                                                                             
info: installing component 'rust-docs'                                                                                                                                                                          
 18.8 MiB /  18.8 MiB (100 %)  12.2 MiB/s in  1s ETA:  0s                                                                                                                                                       
info: installing component 'rust-std'                                                                                                                                                                           
 27.4 MiB /  27.4 MiB (100 %)  16.8 MiB/s in  1s ETA:  0s                                                                                                                                                       
info: installing component 'rustc'                                                                                                                                                                              
 54.2 MiB /  54.2 MiB (100 %)  18.8 MiB/s in  2s ETA:  0s                                                                                                                                                       
info: installing component 'rustfmt'                                                                                                                                                                            
                                                                                                                                                                                                                
  1.64.0-x86_64-unknown-linux-gnu installed - rustc 1.64.0 (a55dd71d5 2022-09-19)                                                                                                                               
                                                                                                                                                                                                                
info: checking for self-updates                                                                                                                                                                                 
info: downloading self-update                                                                                                                                                                                   
info: using existing install for '1.64.0-x86_64-unknown-linux-gnu'                                                                                                                                              
info: default toolchain set to '1.64.0-x86_64-unknown-linux-gnu'                                                                                                                                                
                                                                                                                                                                                                                
  1.64.0-x86_64-unknown-linux-gnu unchanged - rustc 1.64.0 (a55dd71d5 2022-09-19)                                                                                                                               
                                                                                                                                                                                                                
info: downloading component 'rust-std' for 'x86_64-unknown-linux-musl'                                                                                                                                          
info: installing component 'rust-std' for 'x86_64-unknown-linux-musl'                                                                                                                                           
 40.6 MiB /  40.6 MiB (100 %)  16.9 MiB/s in  2s ETA:  0s                                                                                                                                                       
root@Portal-Dev:~#  
```
</div>

Notice the username is now `root`, indicating we are now inside the container. In a different shell we can verify that the container is running:
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~/secure-signer$ docker container ls
CONTAINER ID   IMAGE                                COMMAND       CREATED         STATUS         PORTS     NAMES
2e19c8fc0b24   occlum/occlum:0.29.1-ubuntu20.04     "bash"        4 minutes ago   Up 4 minutes             secure_signer_container_dev
```
</div>

### Using `build_secure_signer.sh`
The `build_secure_signer.sh` is a convenience script for building and running Secure-Signer. If you set the `LOCAL_DEV` environment variable, the script will build/run Rust locally without the Occlum runtime, which may be convenient for developing without an SGX-enabled CPU. Usage:
<div class="code-example" markdown="1">
```bash
root@Puffer-Dev:~# cd secure-signer/ 
root@Puffer-Dev:~/secure-signer# ./build_secure_signer.sh -h
Build and containerize Secure-Signer.
Run "LOCAL_DEV=true ./build_secure_signer.sh <args>" for local dev compilation without SGX dependencies.
usage: build_secure_signer.sh [OPTION]...
    -p <Secure-Signer Server port> default 9001.
    -c clean Cargo then build all
    -b build from cached dependencies
    -x Run Secure-Signer on port set by -p (default 9001)
    -d Build and package the Docker Container Image (assumes "occlum package" has been run)
    -m Measure Secure-Signer's MRENCLAVE and MRSIGNER (assumes this is run in SGX env)
    -t Run all unit tests
    -h <usage> usage help
```
</div>

## Build the Secure-Signer codebase
The following command will compile the codebase, create an Occlum image, and execute Secure-Signer with the default port `9001`.
<div class="code-example" markdown="1">
```bash
./build_secure_signer.sh -b -x
```
</div>

## Running Tests
Use the following command to run unit tests (from inside the Docker container). Note that the tests access a shared filesystem and will be run sequentially.
<div class="code-example" markdown="1">
```bash
./build_secure_signer.sh -t
```
</div>

