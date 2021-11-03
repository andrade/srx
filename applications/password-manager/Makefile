# Copyright 2019 Daniel Andrade
# SPDX-License-Identifier:  MIT

CC := gcc
EDGER := sgx_edger8r
SIGNER := sgx_sign
PROG := titan

SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
SGX_SSL ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxssl
SGX_MODE ?= SIM
SGX_DEBUG ?= 1
SGX_PRERELEASE ?= 0

$(info [SGX_SDK  ] "$(SGX_SDK)")
$(info [SGX_SSL  ] "$(SGX_SSL)")
$(info [SGX_MODE ] "$(SGX_MODE)")
$(info [SGX_DEBUG] "$(SGX_DEBUG)")
$(info [SGX_PRERELEASE] "$(SGX_PRERELEASE)")

EVAL_INCLUDE_LC ?= 0
EVAL_EXCLUDE_LC ?= 0
$(info [ INC LC ] "$(EVAL_INCLUDE_LC)")
$(info [ EXC LC ] "$(EVAL_EXCLUDE_LC)")
CSP_MODE ?= 0
$(info [CSP_MODE] "$(CSP_MODE)")

SRX_API ?=
ifndef SRX_API
$(error SRX_API is not set)
endif

SRX_SDK ?=
ifndef SRX_SDK
$(error SRX_SDK is not set)
endif

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

CPPFLAGS := -I$(SRX_API)
CFLAGS := -m64 -Wall -Wextra -std=c11

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

ifeq ($(EVAL_INCLUDE_LC),1)
	CPPFLAGS += -DEVAL_INCLUDE_LIFECYCLE
else
	CPPFLAGS += -UEVAL_INCLUDE_LIFECYCLE
endif
ifeq ($(EVAL_EXCLUDE_LC),1)
	CPPFLAGS += -DEVAL_EXCLUDE_LIFECYCLE
else
	CPPFLAGS += -UEVAL_EXCLUDE_LIFECYCLE
endif
ifeq ($(CSP_MODE),1)
	CPPFLAGS += -DCSP_ENABLED
else
	CPPFLAGS += -UCSP_ENABLED
endif

ENC_CPPFLAGS := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
		-I$(SGX_SSL)/include \
		-include src/enclave/linux.h \
		-DSQLITE_THREADSAFE=0 -DSQLITE_OS_OTHER=1 -DSQLITE_ENABLE_DESERIALIZE \
		-I$(SRX_PROTOCOL) -I$(SRX_PROTOCOL)/linux -I$(SRX_PROTOCOL)/asn1c \
		-I$(SRX_PROTOCOL)/sgx -D ENABLE_ENCLAVE_ASNONE_CODE=1 \
		$(CPPFLAGS)
ENC_CFLAGS := -fPIC -Wno-implicit-function-declaration \
		-nostdinc -fvisibility=hidden \
		-fpie -fstack-protector -fno-builtin-printf \
		$(CFLAGS)
ENC_LDFLAGS := -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_SDK)/lib64 \
		-L$(SGX_SSL)/lib64 \
		-L$(SRX_SDK) -L$(SRX_PROTOCOL) \
		-L$(SRX_USGX)
ENC_LDLIBS := \
		-lpst-client -lasn1proto-secure \
		-lusgx-secure \
		-Wl,--no-undefined \
		-Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive \
		-lsgx_tsgxssl_crypto \
		-lsgx_tprotected_fs \
		-Wl,--whole-archive -l$(SGX_TRTS) -Wl,--no-whole-archive \
		-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l$(SGX_TSERVICE) -Wl,--end-group \
		-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
		-Wl,--defsym,__ImageBase=0 -Wl,--version-script=src/enclave/enclave.lds

APP_CPPFLAGS := \
		-I$(SGX_SDK)/include \
		-I$(FOOSSL_INCLUDE) \
		-I$(SRX_OPENSSL)/include \
		$(CPPFLAGS)
APP_CFLAGS := -fPIC -Wno-attributes $(CFLAGS)
APP_LDFLAGS := \
		-L$(SGX_SDK)/lib64 -Wl,-rpath,$(SGX_SDK)/sdk_libs,--disable-new-dtags \
		-L$(SGX_SSL)/lib64 -Wl,-rpath,$(SGX_SSL)/sdk_libs,--disable-new-dtags \
		-L$(FOOSSL_LIBRARY) \
		-L$(SRX_OPENSSL)/lib -Wl,-rpath,$(SRX_OPENSSL)/lib,--disable-new-dtags \
		-L$(SRX_SDK) \
		-L$(SRX_USGX)
APP_LDLIBS := \
		-lpst-client-untrusted -lpng -lqrencode `pkg-config --libs gtk+-3.0` \
		-lusgx-normal \
		-lsgx_usgxssl \
		-lsgx_uprotected_fs \
		-l$(SGX_URTS) -l$(SGX_UAE_SERVICE) -lpthread \
		-lfoossl_client -lfoossl_common \
		-lssl -lcrypto \
		-lb64 -lc

all: $(PROG)
	$(call GOOD,,"[  MAKE  ] ","$(notdir $^)")

################################################################
################################ CONFIGURATION
################################################################

.PHONY: clean

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

src/enclave/enclave_t.c src/enclave/enclave_t.h: src/enclave/enclave.edl
	@ $(EDGER) --trusted $< --trusted-dir src/enclave \
			--search-path $(SGX_SDK)/include:$(SGX_SSL)/include \
			--search-path $(SRX_API)
	$(info [  GEN   ] $^  >  $@)

src/enclave/enclave_t.o: src/enclave/enclave_t.c src/enclave/enclave_t.h

src/enclave/enclave.o: src/enclave/enclave.c src/enclave/enclave_t.h src/enclave/sqlite3.h

src/enclave/sqlite3.o: src/enclave/sqlite3.c src/enclave/sqlite3.h
src/enclave/sgxvfs.o: src/enclave/sgxvfs.c src/enclave/sqlite3.h
src/enclave/linux.o: src/enclave/linux.c src/enclave/linux.h

src/enclave/cmd_ui.o: src/enclave/cmd_ui.c src/csysperf.h
src/enclave/crypto.o: src/enclave/crypto.c
src/enclave/db.o: src/enclave/db.c src/csysperf.h
src/enclave/directory_walker.o: src/enclave/directory_walker.c
src/enclave/entry.o: src/enclave/entry.c
src/enclave/pwd-gen.o: src/enclave/pwd-gen.c
src/enclave/regexfind.o: src/enclave/regexfind.c
src/enclave/utils.o: src/enclave/utils.c

SECURE_OBJS := src/enclave/enclave_t.o src/enclave/enclave.o \
		src/enclave/sqlite3.o src/enclave/sgxvfs.o \
		src/enclave/linux.o \
		src/enclave/cmd_ui.o src/enclave/crypto.o src/enclave/db.o src/enclave/entry.o src/enclave/pwd-gen.o src/enclave/utils.o
		#src/enclave/cmd_ui.o src/enclave/crypto.o src/enclave/db.o src/enclave/directory_walker.o src/enclave/entry.o src/enclave/pwd-gen.o src/enclave/regexfind.o src/enclave/utils.o

$(SECURE_OBJS):
	@ $(CC) $(ENC_CPPFLAGS) $(ENC_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

src/enclave/enclave.so: $(SECURE_OBJS)
	@ gcc $(ENC_CPPFLAGS) $(ENC_CFLAGS) $(ENC_LDFLAGS) $^ -o $@ $(ENC_LDLIBS)
	$(info [  LINK  ] $^  >  $@)

enclave.signed.so: src/enclave/enclave.so src/enclave/enclave.config.xml $(KEY_PR)
	@ $(SIGNER) sign \
		-out $@ \
		-enclave src/enclave/enclave.so \
		-config src/enclave/enclave.config.xml \
		-key $(KEY_PR)
	$(info [  SIGN  ] $^  >  $@)

################################################################
################################ UNTRUSTED CODE
################################################################

src/enclave_u.c src/enclave_u.h: src/enclave/enclave.edl
	@ $(EDGER) --untrusted $< --untrusted-dir src \
			--search-path $(SGX_SDK)/include:$(SGX_SSL)/include \
			--search-path $(SRX_API)
	$(info [  GEN   ] $^  >  $@)

src/enclave_u.o: src/enclave_u.c src/enclave_u.h

src/support.o: src/support.c src/enclave_u.h

src/csp.o: src/csp.c
src/cmd_ui.o: src/cmd_ui.c
src/entry.o: src/entry.c
src/utils.o: src/utils.c
src/disk.o: src/disk.c src/disk.h
src/network.o: src/network.c src/network.h
src/titan.o: src/titan.c src/enclave_u.h src/csysperf.h

NORMAL_OBJS := src/enclave_u.o src/support.o \
		src/csp.o \
		src/cmd_ui.o src/entry.o src/utils.o \
		src/disk.o src/network.o \
		src/titan.o

$(NORMAL_OBJS):
	@ $(CC) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

$(PROG): $(NORMAL_OBJS) enclave.signed.so
	@ $(CC) $(APP_CPPFLAGS) $(APP_CFLAGS) $(APP_LDFLAGS) -o $@ $^ $(APP_LDLIBS)
	$(info [  LINK  ] $^  >  $@)

################################################################
################################ MAINTENANCE
################################################################

TRASH := $(PROG) \
		src/enclave/enclave_t.h src/enclave/enclave_t.c \
		src/enclave/enclave.so enclave.signed.so \
		src/enclave_u.h src/enclave_u.c \
		$(SECURE_OBJS) $(NORMAL_OBJS)

clean:
	@rm -rf $(TRASH)
	$(call EVIL,,"[   RM   ] ",$(TRASH))
