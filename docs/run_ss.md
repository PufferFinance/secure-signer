---
layout: default
title: Running Secure-Signer
permalink: /running/
nav_order: 4
has_children: true
---
## Running the Secure-Signer Container

### Prepare a volume
By default, any data created within a Docker container is lost if the container is removed. Secure-Signer maintains our keys and slashing protection databases, so we want this data to persist should anything happen to the container. To do so, we will create a Docker volume called `Secure-Signer-Backup`.
<div class="code-example" markdown="1">
```bash
    docker volume create Secure-Signer-Backup
```
</div>

We can verify the volume exists and inspect it with the following:
<div class="code-example" markdown="1">
```bash
    puffer@Puffer-Dev:~$ docker volume ls
    DRIVER    VOLUME NAME
    local     Secure-Signer-Backup

    puffer@Puffer-Dev:~$ docker volume inspect Secure-Signer-Backup                                                                 [0/1657]
[                                                                                                                                       
    {                                                                                                                                   
        "CreatedAt": "2023-02-01T00:17:30Z",                                                                                            
        "Driver": "local",                                                                                                              
        "Labels": {},
        "Mountpoint": "/var/lib/docker/volumes/Secure-Signer-Backup/_data",
        "Name": "Secure-Signer-Backup",
        "Options": {},
        "Scope": "local"
    }
]
```
</div>


### Start the container
The `pufferfinance/secure_signer:latest` container image can be found [here](https://hub.docker.com/r/pufferfinance/secure_signer). The following command will start running a secure_signer container with the name `secure_signer_container`. Notice we are mounting the volume `Secure-Signer-Backup` to the `/Secure-Signer` enclave directory so any changes to Secure-Signer persist if the container is removed: 
<div class="code-example" markdown="1">
```bash
docker run -itd --network host --mount type=volume,source=Secure-Signer-Backup,destination=/Secure-Signer -v /var/run/aesmd:/var/run/aesmd --device /dev/sgx/enclave --device /dev/sgx/provision --name secure_signer_container pufferfinance/secure_signer:latest 
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
Attach to the container using its name `secure_signer_container`. Notice the username is now `root`, indicating we are now inside the container.
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ docker exec -it secure_signer_container bash
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

The Secure-Signer HTTP server is now running! 

### Run using Docker exec
<div class="code-example" markdown="1">
Alternatively, you can start Secure-Signer without attaching to the container by running the following:
```bash
puffer@Puffer-Dev:~$ docker exec secure_signer_container /bin/bash -c "occlum run /bin/secure-signer 9003"
Starting SGX Secure-Signer: localhost:9003 
```
</div>

### Next steps
Most of the time your consensus client will interface with Secure-Signer, so it is not necessary to learn the full [API](https://pufferfinance.github.io/secure-signer-api-docs/redoc-static.html). However, in the [next section](client) we will learn how to interface with Secure-Signer to perform basic operations like importing and generating validator keys.