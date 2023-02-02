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
    docker volume create —-name Secure-Signer-Backup
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
mkdir secure-signer-backup
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

The Secure-Signer HTTP server is now running! 

## Secure-Signer Cheatsheet
<!-- TODO fix this link when we host api docs -->
The API docs are available [here](). In this section we will demonstrate some convenient commands that can be run directly from the command line. Most of the time your consensus client will interface with Secure-Signer, so it is not necessary to learn the API. However, these commands are useful for verifying that Secure-Signer is correctly running. For more complicated commands, see the [Secure-Signer Client guide](client). Note, for the rest of this section we will assume Secure-Signer is running on port `9003` and `curl` is locally installed.

### Request to generate a BLS key
This command will instruct Secure-Signer to generate and save a new BLS private key. Returned is the hex-encoded BLS public key.
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ curl -X POST localhost:9003/eth/v1/keygen/bls
{"pk_hex":"0xa972dbe08a82a63a687143da150f7938311bdbd8c92d047680fd112f899d3e1023913be387663a898b9a31896b33f173"}
```
</div>

### Request to list generated BLS keys
This command will instruct Secure-Signer list the hex-encoded public keys for each of the BLS private keys it generated and saved.
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ curl -X GET localhost:9003/eth/v1/keygen/bls                                                                       
{"data":[{"pubkey":"0xa972dbe08a82a63a687143da150f7938311bdbd8c92d047680fd112f899d3e1023913be387663a898b9a31896b33f173"}]}
```
</div>

### Request to perform Remote Attestation
This command will instruct Secure-Signer to perform Remote Attestation and commit to the BLS public key that we just generated.
<div class="code-example" markdown="1">
```bash
puffer@Puffer-Dev:~$ curl -X POST localhost:9003/eth/v1/remote-attestation/0xa972dbe08a82a63a687143da150f7938311bdbd8c92d047680fd112f899d3e1023913be387663a898b9a31896b33f173
{"pub_key":"0xa972dbe08a82a63a687143da150f7938311bdbd8c92d047680fd112f899d3e1023913be387663a898b9a31896b33f173","evidence":{"raw_report":"{\"id\":\"136868058234963068558777257691568982123\",\"timestamp\":\"2023-01-31T23:29:43.986601\",\"version\":4,\"epidPseudonym\":\"EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go=\",\"advisoryURL\":\"https://security-center.intel.com\",\"advisoryIDs\":[\"INTEL-SA-00334\",\"INTEL-SA-00615\"],\"isvEnclaveQuoteStatus\":\"SW_HARDENING_NEEDED\",\"isvEnclaveQuoteBody\":\"AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAfAAAAAAAAAOFQXvlL3nfc1fBm4Og+hglPv3glo9t3u6Oox972dfkPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACpctvgioKmOmhxQ9oVD3k4MRvb2MktBHaA/REviZ0+ECORO+OHZjqJi5oxiWsz8XMAAAAAAAAAAAAAAAAAAAAA\"}","sign[5/1495]t":"hiVcYQ4uZ6o+nwiWHdrZ9Laklb32ihd5Ea6g+HBGIFVFjm/Arsg0ORALnGuS49PGinPEARYISw5rBXPAS7yJDbkXcFWW8L7Y2xZdrkciDZaKAumF5GsVxaX3tf/Jl+N+YejWeSR0Djziu1KMnBItbiH/bUTh3f3HbS8FVWNzl35ml4FjlnP9DQVAQEr77/hPCUD/5oOAFUdl5oxajL/BhzlUzef8A/UqV09DAu+EfZ19EbJjkSgltrpdTrNpzZSuW82FtTyux8Ko+CPwj+qAjf/FOwr6bQlYvAfsfOtoMprKM2B9/GEoOjotdh+b0dhCu9TAlytvLf3oMnzlimcumA==","signing_cert":"-----BEGIN CERTIFICATE-----\nMIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw\nMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh\nbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk\nSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+t\nbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId\ncv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv\nLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhA\nImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8\ngZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh\nMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIG\nwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk\nc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl\ncG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r\nRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9\nlpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv\nWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd\nZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY\n6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7\n2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2\ntQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbq\nd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy\nMzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL\nU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD\nDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G\nCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e\nLmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh\nrgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT\nL/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe\nNpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ\nbyinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H\nafuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf\n6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM\nRoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX\nMFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50\nL0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW\nBBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr\nNXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq\nhkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir\nIEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ\nsFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi\nzLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra\nUd4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA\n152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB\n3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O\nDD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv\nDaVzWh5aiEx+idkSGMnX\n-----END CERTIFICATE-----\n"}}

```
</div>