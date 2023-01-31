---
layout: default
title: Installation
permalink: /Installation/
nav_order: 2
has_children: true
---

## Prereqs

Ubuntu20.04

## Installing Docker

The Secure-Signer runtime has been containerized for ease of deployment. The first step is to install Docker.

<div class="code-example" markdown="1">
```bash

sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
apt-cache policy docker-ce
sudo apt install -y docker-ce
sudo systemctl status docker
sudo groupadd docker
sudo usermod -aG docker $USER

```

```
