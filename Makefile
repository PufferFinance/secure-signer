# working directory of this Makefile
THISDIR=$(PWD)

# the name of the .json file that has epid remote attestation credentials
RA_CONFIG_NAME=ra_config.json

# name of occlum instance
ENCLAVE_NAME=secure_signer_occlum

# the path to the occlum instance
INSTANCE_PATH=$(THISDIR)/$(ENCLAVE_NAME)

# dir of shared libs
MUSL_DIR=/usr/local/occlum/x86_64-linux-musl/

# occlum executable
OCCLUM=occlum

# optional flags to run
FLAGS?=""

# optional flag for debugging
LEVEL?=""

# binary name
BINARY_NAME=secure-signer

# port to run secure signer
PORT = 9001

LEVEL=""


.PHONY: all
all: build measure

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
	OCCLUM_LOG_LEVEL=$(LEVEL) $(OCCLUM) run /bin/$(BINARY_NAME) $(PORT)

.PHONY: measure
measure: 
	@cd $(INSTANCE_PATH) && \
	echo "MRENCLAVE: 0x$$($(OCCLUM) print mrenclave)" && \
	echo "MRSIGNER: 0x$$($(OCCLUM) print mrsigner)"
