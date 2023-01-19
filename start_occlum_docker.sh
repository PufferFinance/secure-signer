# end old container
sudo docker container rm secure_signer_container

# start new container
sudo docker run -itd --privileged -v ~/secure-signer:/root/secure-signer \
                                  -v /dev/sgx_enclave:/dev/sgx/enclave --name "secure_signer_container" \
                                  -v /dev/sgx_provision:/dev/sgx/provision \
                                  --network="host" \
                                  occlum/occlum:latest-ubuntu20.04

sudo docker ps
echo "select the CONTAINER ID from the container named 'secure_signer_container' then run 'sudo docker attach <container_id>"
