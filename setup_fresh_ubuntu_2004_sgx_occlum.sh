# install prereqs
sudo apt update 
sudo apt upgrade -y

sudo DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends libcurl4-openssl-dev libssl-dev libprotobuf-dev libfuse-dev autoconf automake make cmake libtool gdb python jq ca-certificates gnupg python3-dev wget vim python3.8-venv npm

sudo apt install -y build-essential ocaml automake autoconf libtool wget python libssl-dev mosh tmux docker-compose

# install the necessary sgx libs / intel enclaves

echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list

wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add

sudo apt update 

sudo apt install -y libsgx-epid libsgx-quote-ex libsgx-dcap-ql libsgx-urts libsgx-uae-service 

sudo apt install -y libsgx-urts libsgx-dcap-ql libsgx-dcap-default-qpl 

service aesmd status

# install occlum codebase

git clone https://github.com/occlum/occlum.git

echo 'deb [arch=amd64] https://occlum.io/occlum-package-repos/debian focal main' | tee /etc/apt/sources.list.d/occlum.list

wget -qO - https://occlum.io/occlum-package-repos/debian/public.key | sudo apt-key add -

sudo apt update 

sudo apt install -y occlum

echo "source /etc/profile" >> $HOME/.bashrc

# install docker deps

sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
apt-cache policy docker-ce
sudo apt install -y docker-ce
sudo systemctl status docker
