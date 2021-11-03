LIB_YAPI ?= ../yapi
LIB_BTC ?= ../../external/libbtc-sgx
LIB_BTC_RAW ?= ../../external/libbtc-original
SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
SGX_MODE ?= SIM
SGX_DEBUG ?= 1
SGX_PRERELEASE ?= 0
CSP_MODE ?= 0

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

CPPFLAGS :=
CFLAGS := -m64 -Wall -Wextra -std=c11
LDFLAGS := -L. -Wl,-rpath,.
LDLIBS :=

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

ifeq ($(CSP_MODE),1)
	CPPFLAGS += -DCSP_ENABLED
else
	CPPFLAGS += -UCSP_ENABLED
endif

# libyapi
CPPFLAGS += -I$(LIB_YAPI)/include
LDFLAGS += -L$(LIB_YAPI)/src -Wl,-rpath,$(LIB_YAPI)/src,--disable-new-dtags
LDLIBS += -lyapi

# Libraries to enable SGX
CPPFLAGS += -I$(SGX_SDK)/include
LDFLAGS += -L$(SGX_SDK)/lib64 -Wl,-rpath,$(SGX_SDK)/sdk_libs,--disable-new-dtags
LDLIBS += -l$(SGX_URTS) -l$(SGX_UAE_SERVICE) -lpthread

CPPFLAGS += -I$(SRX_OPENSSL)/include
LDFLAGS += -L$(SRX_OPENSSL)/lib -Wl,-rpath,$(SRX_OPENSSL)/lib,--disable-new-dtags
LDLIBS += -lssl -lcrypto

$(info LIB_YAPI  = $(LIB_YAPI))
$(info LIB_BTC  = $(LIB_BTC))
$(info SGX_SDK   = $(SGX_SDK))
$(info SGX_DEBUG = $(SGX_DEBUG))
$(info SGX_PRERELEASE = $(SGX_PRERELEASE))
$(info CSP_MODE = $(CSP_MODE))
$(info ----------------)

all: yapitool

src/disk.o: src/disk.c
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
	@echo "[  CC  ]   ⇠   $<"

src/cmd_ui.o: src/cmd_ui.c  src/csysperf.h
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
	@echo "[  CC  ]   ⇠   $<"

src/yapitool.o: src/yapitool.c  src/csysperf.h
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
	@echo "[  CC  ]   ⇠   $<"

yapitool: src/yapitool.o src/cmd_ui.o src/disk.o
	@$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@
	@ln --force -s ../yapi/src/sgx/enclave.signed.so enclave.signed.so
	#@ln --force -s ../yapi/src/libyapi.so libyapi.so
	@echo "[ LINK ]   ⇢   $@"

TORM := yapitool src/yapitool.o src/cmd_ui.o src/disk.o enclave.signed.so

clean:
	@$(RM) $(TORM)
	@echo "[  RM  ]   ⇠   $(TORM)"
