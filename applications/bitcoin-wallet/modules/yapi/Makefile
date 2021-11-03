CC := gcc
SGX_EDGER8R ?= $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGN ?= $(SGX_SDK)/bin/x64/sgx_sign

LIB_BTC ?= ../../external/libbtc-sgx
# workaround to support two compiled versions, one with SGX and one without
LIB_BTC_RAW ?= ../../external/libbtc-original
SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
SGX_SSL ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxssl
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
SGX_PRERELEASE ?= 0

# Name of the library to build
LIB_NAME ?= enclave

LIB_NORMAL := $(LIB_NAME).so
LIB_SIGNED := $(LIB_NAME).signed.so

SGX_CONFIG := enclave.config.xml

SRX_API ?=
ifndef SRX_API
$(error SRX_API is not set)
endif

SRX_SDK ?=
ifndef SRX_SDK
$(error SRX_SDK is not set)
endif

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

SGX_COMMON_CFLAGS := -m64 -Wall -Wextra -std=c11

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

SGX_APP_CPPFLAGS := \
	-Iinclude \
	-I$(LIB_BTC_RAW)/include \
	-I$(SRX_API) \
	-I$(FOOSSL_INCLUDE) \
	-I$(SRX_OPENSSL)/include \
	-I$(SGX_SDK)/include \
	-I$(SGX_SSL)/include

SGX_APP_CFLAGS := $(SGX_COMMON_CFLAGS) \
	-fPIC -Wno-attributes

SGX_APP_LDFLAGS := \
	-L$(LIB_BTC_RAW)/.libs \
	-L$(LIB_BTC_RAW)/src/secp256k1/.libs \
	-Wl,-rpath,$(LIB_BTC_RAW)/.libs,--disable-new-dtags \
	-L$(SRX_SDK) -L$(SRX_PROTOCOL) -L$(SRX_USGX) \
	-L$(FOOSSL_LIBRARY) \
	-L$(SRX_OPENSSL)/lib -Wl,-rpath,$(SRX_OPENSSL)/lib,--disable-new-dtags \
	-L$(SGX_SDK)/lib64 \
	-L$(SGX_SSL)/lib64

SGX_APP_LDLIBS := \
	-Wl,-Bstatic -lbtc-original -lsecp256k1 \
	-Wl,-Bdynamic -lgmp \
	-lpst-client-untrusted -lpng -lqrencode `pkg-config --libs gtk+-3.0` \
	-lusgx-normal \
	-lsgx_usgxssl \
	-lsgx_uprotected_fs \
	-l$(SGX_URTS) -l$(SGX_UAE_SERVICE) -lpthread \
	-lfoossl_client -lfoossl_common \
	-lssl -lcrypto \
	-lb64 -lc

SGX_ENC_CPPFLAGS := \
	-Iinclude \
	-I$(LIB_BTC)/include \
	-I$(SRX_API) \
	-I$(SGX_SDK)/include \
	-I$(SGX_SDK)/include/tlibc \
	-I$(SGX_SDK)/include/libcxx \
	-I$(SGX_SSL)/include \
	-I$(SRX_PROTOCOL) -I$(SRX_PROTOCOL)/linux -I$(SRX_PROTOCOL)/asn1c \
	-I$(SRX_PROTOCOL)/sgx -D ENABLE_ENCLAVE_ASNONE_CODE=1 \
	$(CPPFLAGS)

SGX_ENC_CFLAGS := $(SGX_COMMON_CFLAGS) \
	-fPIC -Wno-implicit-function-declaration \
	-nostdinc -fvisibility=hidden \
	-fpie -fstack-protector -fno-builtin-printf \
	$(CFLAGS)

SGX_ENC_LDFLAGS := \
	-nostdlib -nodefaultlibs -nostartfiles \
	-L$(LIB_BTC)/.libs \
	-L$(LIB_BTC)/src/secp256k1/.libs \
	-L$(SRX_SDK) -L$(SRX_PROTOCOL) -L$(SRX_USGX) \
	-L$(SGX_SDK)/lib64 \
	-L$(SGX_SSL)/lib64

SGX_ENC_LDLIBS := \
	-lbtc -lsecp256k1 \
	-lpst-client -lasn1proto-secure -lusgx-secure \
	-Wl,--no-undefined \
	-Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive \
	-lsgx_tsgxssl_crypto \
	-lsgx_tprotected_fs \
	-Wl,--whole-archive -l$(SGX_TRTS) -Wl,--no-whole-archive \
	-Wl,--start-group \
	-lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l$(SGX_TSERVICE) \
	-Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0 -Wl,--version-script=src/sgx/enclave.lds

ifneq ($(SGX_ARCH),x64)
$(error bad arch, expected x64, got $(SGX_ARCH))
endif

ifeq ($(SGX_KEY),)
$(error missing private key path, please set $$SGX_KEY)
endif

$(info LIB_BTC   = $(LIB_BTC))
$(info SGX_SDK   = $(SGX_SDK))
$(info SGX_SSL   = $(SGX_SSL))
$(info SGX_MODE  = $(SGX_MODE))
$(info SGX_ARCH  = $(SGX_ARCH))
$(info SGX_DEBUG = $(SGX_DEBUG))
$(info LIB_NAME  = $(LIB_NAME))
$(info ----------------)

#all: src/sgx/$(LIB_SIGNED) src/libyapi.a
all: src/sgx/$(LIB_SIGNED) src/libyapi.so.1.0.0

##                COMMON                ##

EDL_OBJS := \
		src/sgx/u/keystore_u.c src/sgx/u/keystore_u.h \
		src/sgx/t/keystore_t.c src/sgx/t/keystore_t.h

$(EDL_OBJS): $(SGX_EDGER8R) src/sgx/keystore.edl
	cd src/sgx/ && $(SGX_EDGER8R) keystore.edl \
			--search-path $(SGX_SDK)/include \
			--search-path $(SGX_SSL)/include \
			--search-path $(SRX_API) \
			--search-path $(SRX_USGX)/include \
			--untrusted-dir u/ --trusted-dir t/
	@echo "[ GEN  ]   ⇢   $(EDL_OBJS)"

##                UNTRUSTED                ##

src/sgx/u/keystore_u.o: src/sgx/u/keystore_u.c
src/sgx/u/keystore.o: src/sgx/u/keystore.c src/sgx/u/keystore_u.h
src/sgx/u/network.o: src/sgx/u/network.c
src/yapi.o: src/yapi.c

SECURE_OBJS := \
		src/sgx/u/keystore_u.o \
		src/sgx/u/keystore.o \
		src/sgx/u/network.o \
		src/yapi.o

$(SECURE_OBJS):
	@$(CC) $(SGX_APP_CPPFLAGS) $(SGX_APP_CFLAGS) -c $< -o $@
	@echo "[  CC  ]   ⇠   $<"

#src/libyapi.a: src/yapi.o src/sgx/u/keystore.o src/sgx/u/keystore_u.o
#	@$(AR) rcs $@ $^
#	@echo "[ LINK ]   ⇢   $@"

src/libyapi.so.1.0.0: $(SECURE_OBJS)
	@$(CC) $(SGX_APP_CPPFLAGS) $(SGX_APP_CFLAGS) $(SGX_APP_LDFLAGS) -shared $^ -o $@ $(SGX_APP_LDLIBS)
	@ln --force -s libyapi.so.1.0.0 src/libyapi.so.1
	@ln --force -s libyapi.so.1.0.0 src/libyapi.so
	@echo "[ LINK ]   ⇢   $@"
#-shared  -Wl,--default-symver -Wl,-soname,libyapi.so.1

##                TRUSTED                ##

src/sgx/t/keystore_t.o: src/sgx/t/keystore_t.c
	@$(CC) $(SGX_ENC_CPPFLAGS) $(SGX_ENC_CFLAGS) -c $< -o $@
	@echo "[  CC  ]   ⇠   $<"

src/sgx/t/keystore.o: src/sgx/t/keystore.c src/sgx/t/keystore_t.h
	@$(CC) $(SGX_ENC_CPPFLAGS) $(SGX_ENC_CFLAGS) -c $< -o $@
	@echo "[  CC  ]   ⇢   $@"

src/sgx/$(LIB_NORMAL): src/sgx/t/keystore.o src/sgx/t/keystore_t.o
	@$(CC) $(SGX_ENC_CPPFLAGS) $(SGX_ENC_CFLAGS) $(SGX_ENC_LDFLAGS) -static $^ -o $@ $(SGX_ENC_LDLIBS)
	@echo "[ LINK ]   ⇢   $@"

src/sgx/$(LIB_SIGNED): src/sgx/$(LIB_NORMAL) $(SGX_KEY)
	@cd src/sgx/ && $(SGX_SIGN) sign \
			-key $(SGX_KEY) \
			-enclave $(LIB_NORMAL) \
			-out $(LIB_SIGNED) \
			-config $(SGX_CONFIG) > /dev/null 2>&1
	@echo "[ SIGN ]   ⇢   $@"

# List of objects to remove
TORM := \
		$(EDL_OBJS) \
		$(SECURE_OBJS) \
		src/libyapi.a \
		src/libyapi.so src/libyapi.so.1 src/libyapi.so.1.0.0 \
		src/sgx/t/keystore.o src/sgx/t/keystore_t.o \
		src/sgx/$(LIB_NORMAL) \
		src/sgx/$(LIB_SIGNED)

clean:
	@rm --force $(TORM)
	@echo "[  RM  ]   ⇠   $(TORM)"

print-%  : ; @echo $* = $($*)
