---
layout: default
title: Development
permalink: /development/
nav_order: 4
has_children: false
---
This guide will explain how to setup the Secure-Signer development environment.
## Running the Secure-Signer Container
### Start the container
The secure_signer container image can be found [here](https://hub.docker.com/r/pufferfinance/secure_signer). The following will start running a secure_signer container with the name `secure_signer_container` and with its ports exposed:
<div class="code-example" markdown="1">
```bash
docker run -itd --network host -v /var/run/aesmd:/var/run/aesmd --device /dev/sgx/enclave --device /dev/sgx/provision --name secure_signer_container pufferfinance/secure_signer:latest 
```
</div>

Verify that the container is running:

<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ docker container ls                                                                                                
CONTAINER ID   IMAGE                                COMMAND   CREATED         STATUS         PORTS     NAMES
3ce85f5a1d33   pufferfinance/secure_signer:latest   "bash"    4 seconds ago   Up 3 seconds             secure_signer_container
```
</div>

### Attach to the container
Attach to the container using its name `secure_signer_container`. Notice the username is now `root`.
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ docker exec -it secure_signer_container bash                                                               [0/1430]
root@Puffer-Dev:/Secure-Signer# 
```
</div>

### Run Secure-Signer
The Secure-Signer enclave is built using the [Occlum LibOS](https://github.com/occlum/occlum). To start Secure-Signer we will use the `occlum run` command and point to the `secure-signer` binary stored within the Occlum enclave image and specify port `9003`.
<div class="code-example" markdown="1">
```bash
root@Puffer-Dev:/Secure-Signer# occlum run /bin/secure-signer 9003                                                                      
Starting SGX Secure-Signer: localhost:9003 
```
</div>

## Running Tests