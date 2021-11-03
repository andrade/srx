CC := gcc
EDGER := sgx_edger8r
SIGNER := sgx_sign

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
SGX_SSL ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxssl
$(info [ SGX_DIR] "$(SGX_SDK)")
$(info [ SSL_DIR] "$(SGX_SSL)")

SRX_API ?=
ifndef SRX_API
$(error SRX_API is not set)
endif

SRX_SDK ?=
ifndef SRX_SDK
$(error SRX_SDK is not set)
endif

SRX_OPENSSL ?=
ifndef SRX_OPENSSL
$(error Environment variable `SRX_OPENSSL` is not set)
endif
$(info [SRX_OPENSSL] "$(SRX_OPENSSL)")

## Additional include paths for EDL (define via CLI when calling make)
#EDL_INC_PATH ?=
## Additional library paths for EDL (define via CLI when calling make)
#EDL_LIB_PATH ?=
#CHANGED  use $(SRX_USGX) instead with or without include/ as necessary

SGX_MODE ?= SIM
SGX_DEBUG ?= 1
SGX_PRERELEASE ?= 0

$(info [SGX_MODE] "$(SGX_MODE)")
$(info [SGX_DEBUG] "$(SGX_DEBUG)")
$(info [SGX_PRERELEASE] "$(SGX_PRERELEASE)")

define GOOD
	@echo -n $1
	@tput setaf 6
	@echo -n $2
	@tput sgr0
	@echo $3
endef

define EVIL
	@echo -n $1
	@tput setaf 3
	@echo -n $2
	@tput sgr0
	@echo $3
endef

$(info ------------------------------------------------------------------------)

ifeq ($(SGX_MODE),HW)
	SGX_TRTS := sgx_trts
	SGX_TSERVICE := sgx_tservice
	SGX_UAE_SERVICE := sgx_uae_service
	SGX_URTS := sgx_urts
else
	SGX_TRTS := sgx_trts_sim
	SGX_TSERVICE := sgx_tservice_sim
	SGX_UAE_SERVICE := sgx_uae_service_sim
	SGX_URTS := sgx_urts_sim
endif

CFLAGS := -m64 -Wall -Wextra \
		-I$(SRX_USGX)/include \
		-I$(SRX_API)

ifeq ($(SGX_DEBUG),1)
	CFLAGS += -O0 -g
	CFLAGS += -DDEBUG -UNDEBUG -UEDEBUG
else
	CFLAGS += -O2
ifeq ($(SGX_PRERELEASE),1)
	CFLAGS += -UDEBUG -DNDEBUG -DEDEBUG
else
	CFLAGS += -UDEBUG -DNDEBUG -UEDEBUG
endif # SGX_PRERELEASE
endif

ifeq ($(SGX_PRERELEASE),1)
	CFLAGS += -O2
	CFLAGS += -UDEBUG -DNDEBUG -DEDEBUG
else
endif

TLIB_IPATHS := -I$(SGX_SDK)/include \
		-I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/epid
TLIB_CFLAGS := $(CFLAGS) -std=c11 \
		-Wno-implicit-function-declaration -nostdinc -fpie -fstack-protector \
		-fno-builtin-printf $(TLIB_IPATHS)

ENC_IPATHS := -I$(SRX_SDK) \
		-I$(SGX_SDK)/include \
		-I$(SGX_SDK)/include/tlibc \
		-I$(SGX_SDK)/include/stlport \
		-I$(SGX_SSL)/include \
		-I$(SRX_PROTOCOL) -I$(SRX_PROTOCOL)/linux -I$(SRX_PROTOCOL)/asn1c -I$(SRX_PROTOCOL)/sgx -D ENABLE_ENCLAVE_ASNONE_CODE=1
ENC_CFLAGS := $(CFLAGS) -fPIC -Wno-implicit-function-declaration \
		-std=c11 -nostdinc -fvisibility=hidden \
		-fpie -fstack-protector -fno-builtin-printf \
		$(ENC_IPATHS)
ENC_LDFLAGS := $(CFLAGS) \
		-nostdlib -nodefaultlibs -nostartfiles \
		-L$(SGX_SDK)/lib64 \
		-L$(SGX_SSL)/lib64 \
		-L$(SRX_SDK) \
		-L$(SRX_USGX) \
		-L$(SRX_PROTOCOL)
ENC_LDLIBS := -lpst-client -lusgx-secure -lasn1proto-secure \
		-Wl,--no-undefined \
		-Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive \
		-lsgx_tsgxssl_crypto \
		-lsgx_tprotected_fs \
		-Wl,--whole-archive -l$(SGX_TRTS) -Wl,--no-whole-archive \
		-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l$(SGX_TSERVICE) -Wl,--end-group \
		-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
		-Wl,--defsym,__ImageBase=0 -Wl,--version-script=enclave.lds
#-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group

APP_CFLAGS := $(CFLAGS) \
		-I$(SRX_SDK) \
		-I$(SGX_SDK)/include \
		-I$(FOOSSL_INCLUDE) \
		-I$(SRX_OPENSSL)/include \
		-fPIC -Wno-attributes
		#-I$(SGX_SSL)/include
APP_LDFLAGS := -L$(SGX_SDK)/lib64 \
		-Wl,-rpath,$(SGX_SDK)/sdk_libs,--disable-new-dtags \
		-L$(FOOSSL_LIBRARY) \
		-L$(SRX_OPENSSL)/lib -Wl,-rpath,$(SRX_OPENSSL)/lib,--disable-new-dtags \
		-L$(SRX_SDK) \
		-L$(SRX_USGX)
		#-L$(SGX_SSL)/lib64/debug
		#-Wl,-rpath,$(SGX_SSL)/lib64/debug,--disable-new-dtags
APP_LDLIBS := \
		-lpst-client-untrusted -lpng -lqrencode `pkg-config --libs gtk+-3.0` \
		-lusgx-normal \
		-lsgx_uprotected_fs \
		-l$(SGX_URTS) -l$(SGX_UAE_SERVICE) -lpthread \
		-lfoossl_client -lfoossl_common \
		-lssl -lcrypto \
		-lb64 -lc
		#-lsgx_usgxssl

EDL_SEARCH_PATHS := .:$(SRX_API):$(SGX_SDK)/include:$(SGX_SSL)/include:$(SRX_USGX)/include


all: app_ex
	$(call GOOD,,"[  MAKE  ] ","$(notdir $^)")

################################################################
################################ MANAGEMENT
################################################################

.PHONY: clean

################################################################
################################ CRYPTO
################################################################

KEY_PR := key.pem

genkey:
	@openssl genrsa -3 -out $(KEY_PR) 3072
	$(call GOOD,,"[ GENKEY ] ","$^  >  $@")
	$(info [ GENKEY ] Enclave private key is left untouched by clean.)
	$(info [ GENKEY ] Explicitly use delkey to delete it.)

delkey:
	@rm -f $(KEY_PR)
	$(call EVIL,,"[ DELKEY ] ","$^  >  $@")

$(KEY_PR):
	$(call GOOD,"[ KEY_PR ] Create private key with ","make genkey",)
	$(call EVIL,"[ KEY_PR ] Delete private key with ","make delkey",)

################################################################
################################ TRUSTED CODE
################################################################

enclave_t.c enclave_t.h: enclave.edl $(SRX_API)/srx.edl
	@$(EDGER) --trusted enclave.edl --search-path $(EDL_SEARCH_PATHS)
	$(info [  GEN   ] $^  >  $@)

enclave_t.o: enclave_t.c
	@$(CC) $(ENC_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

%.o: %.c enclave_t.h
	@ $(CC) $(ENC_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

enclave.so: enclave_t.o enclave.o
	@ $(CC) $(ENC_CFLAGS) $(ENC_LDFLAGS) -o $@ $^ $(ENC_LDLIBS)
	$(info [  GEN   ] $^  >  $@)

enclave.signed.so: enclave.so \
		enclave.config.xml $(KEY_PR)
	@$(SIGNER) sign -key $(KEY_PR) -enclave enclave.so -out enclave.signed.so -config enclave.config.xml
	$(info [  SIGN  ] $^  >  $@)

################################################################
################################ UNTRUSTED CODE
################################################################

enclave_u.c enclave_u.h: enclave.edl $(SRX_API)/srx.edl
	@$(EDGER) --untrusted $< --search-path $(EDL_SEARCH_PATHS)
	$(info [  GEN   ] $^  >  $@)

enclave_u.o: enclave_u.c enclave_u.h

mainapp.o: mainapp.c enclave_u.h

support.o: support.c enclave_u.h

network.o: network.c network.h enclave_u.h

disk.o: disk.c disk.h

CLIENT_NORMAL_OBJS := enclave_u.o mainapp.o support.o network.o disk.o

$(CLIENT_NORMAL_OBJS):
	@ $(CC) $(APP_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

app_ex: $(CLIENT_NORMAL_OBJS) enclave.signed.so
	@$(CC) $(APP_CFLAGS) $(APP_LDFLAGS) -o $@ $^ $(APP_LDLIBS)
	$(info [  LINK  ] $^  >  $@)

################################################################
################################ MAINTENANCE
################################################################

TRASH := app_ex \
		enclave_t.h enclave_t.c enclave_t.o \
		enclave.o enclave.so enclave.signed.so \
		enclave_u.h enclave_u.c enclave_u.o \
		disk.o network.o support.o mainapp.o
clean:
	@rm -rf $(TRASH)
	$(call EVIL,,"[   RM   ] ",$(TRASH))
