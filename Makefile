# working directory of this Makefile
THISDIR=$(PWD)

# the name of the .json file that has epid remote attestation credentials
RA_CONFIG_NAME=ra_config.json

# the path to the occlum instance
INSTANCE_PATH=$(THISDIR)/$(ENCLAVE_NAME)

# dir of shared libs
MUSL_DIR=/usr/local/occlum/x86_64-linux-musl/

# occlum executable
OCCLUM=/root/occlum/build/bin/occlum

# worker id
ID?=0

# optional flags to run
FLAGS?=""

# optional flag for debugging
LEVEL?=""

.PHONY: all
all: build measure run

.PHONY: build
build:
	@ # compiles the epid RA cpp code into a single static lib
	./download_and_build.sh

	@ # compile the leader and worker rust code
	@export OPENSSL_DIR=$(MUSL_DIR) && \
	occlum-cargo build 

	@ # initialize occlum instance
	@rm -rf $(INSTANCE_PATH); 
	@mkdir -p $(INSTANCE_PATH) && \
	cd $(INSTANCE_PATH) && \
	$(OCCLUM) init || exit 1;
	@echo "Finished initializing occlum instance";

	@ # copy required rust deps into image
	@cd $(INSTANCE_PATH) && \
	copy_bom -f ../$(BINARY_NAME)-rust-config.yaml --root image --include-dir /opt/occlum/etc/template;

	@ # copy files into the occlum image for web access then build enclave
	@mkdir -p $(INSTANCE_PATH)/image/etc                                                      && \
	mkdir -p $(INSTANCE_PATH)/image/etc/certs                                                 && \
	cp Occlum.json $(INSTANCE_PATH)           												  && \
	cp /etc/resolv.conf $(INSTANCE_PATH)/image/etc                                            && \
	cp /etc/hosts $(INSTANCE_PATH)/image/etc                                                  && \
	cp $(THISDIR)/conf/$(RA_CONFIG_NAME) $(INSTANCE_PATH)/image/etc/                          && \
	cd $(INSTANCE_PATH) && $(OCCLUM) build;

.PHONY: run
run: 
	@cd $(INSTANCE_PATH) && \
	OCCLUM_LOG_LEVEL=$(LEVEL) $(OCCLUM) run /bin/$(BINARY_NAME) $(FLAGS)

.PHONY: measure
measure: 
	@sgx_sign dump -enclave $(INSTANCE_PATH)/build/lib/libocclum-libos.signed.so -dumpfile $(ENCLAVE_NAME)/measurements.txt
	@echo "enclave measurements dumped to 'measurements.txt', (MRENCLAVE, MRSIGNER):"
	@sed -n -e '/enclave_hash.m/,/metadata->enclave_css.body.isv_prod_id/p' ./$(ENCLAVE_NAME)/measurements.txt |head -3|tail -2|xargs|sed 's/0x//g'|sed 's/ //g' > $(ENCLAVE_NAME)/MRENCLAVE
	@cat $(ENCLAVE_NAME)/MRENCLAVE
	@sed -n -e '/mrsigner->/,/*/p' ./$(ENCLAVE_NAME)/measurements.txt |head -3|tail -2|xargs|sed 's/0x//g'|sed 's/ //g' > $(ENCLAVE_NAME)/MRSIGNER
	@cat $(ENCLAVE_NAME)/MRSIGNER

.PHONY: leader
leader:
	@ENCLAVE_NAME=leader_instance \
	BINARY_NAME=leader \
	make;

.PHONY: worker
worker:
	@ENCLAVE_NAME=worker_$(ID)_instance \
	BINARY_NAME=worker \
	make;