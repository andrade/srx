CC := gcc
EDGER := sgx_edger8r
SIGNER := sgx_sign

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
$(info [ SGX_DIR] "$(SGX_SDK)")

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

CFLAGS := -m64 -O0 -g -Wall -Wextra

TLIB_IPATHS := -I$(SGX_SDK)/include \
		-I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/epid
TLIB_CFLAGS := $(CFLAGS) -std=c11 \
		-Wno-implicit-function-declaration -nostdinc -fpie -fstack-protector \
		-fno-builtin-printf $(TLIB_IPATHS) -DDEBUG

ENC_IPATHS := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I../secure-token-dummy
ENC_CFLAGS := $(CFLAGS) -Wno-implicit-function-declaration -std=c11 -nostdinc -fvisibility=hidden -fpie -fstack-protector -fno-builtin-printf $(ENC_IPATHS)
ENC_LFLAGS := $(CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_SDK)/lib64 -Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive -Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wl,--version-script=enclave.lds -L../secure-token-dummy -ldummy

APP_CFLAGS := $(CFLAGS) -I$(SGX_SDK)/include -fPIC -Wno-attributes \
		-DDEBUG -UNDEBUG -UEDEBUG
APP_LDFLAGS := -L$(SGX_SDK)/lib64 \
		-Wl,-rpath,$(SGX_SDK)/sdk_libs,--disable-new-dtags
APP_LDLIBS := -lsgx_urts_sim -lsgx_uae_service_sim -lpthread -lc


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

enclave_t.c enclave_t.h: enclave.edl ../secure-token-api/srx.edl
	@$(EDGER) --trusted enclave.edl --search-path .:../secure-token-api
	$(info [  GEN   ] $^  >  $@)

enclave_t.o: enclave_t.c
	@$(CC) $(ENC_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

%.o: %.c enclave_t.h
	@ gcc $(ENC_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

enclave.so: enclave_t.o enclave.o
	@ gcc $^ -o $@ $(ENC_LFLAGS)
	$(info [  GEN   ] $^  >  $@)

enclave.signed.so: enclave.so \
		enclave.config.xml $(KEY_PR)
	@$(SIGNER) sign -key $(KEY_PR) -enclave enclave.so -out enclave.signed.so -config enclave.config.xml
	$(info [  SIGN  ] $^  >  $@)

################################################################
################################ UNTRUSTED CODE
################################################################

enclave_u.c enclave_u.h: enclave.edl ../secure-token-api/srx.edl
	@$(EDGER) --untrusted $< --search-path .:../secure-token-api
	$(info [  GEN   ] $^  >  $@)

enclave_u.o: enclave_u.c
	@$(CC) $(APP_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

%.o: %.c enclave_u.h
	@ gcc $(APP_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

app_ex: enclave_u.o support.o mainapp.o enclave.signed.so
	@$(CC) $(APP_CFLAGS) $(APP_LDFLAGS) -o $@ $^ $(APP_LDLIBS)
	$(info [  LINK  ] $^  >  $@)

################################################################
################################ MAINTENANCE
################################################################

TRASH := app_ex \
		enclave_t.h enclave_t.c enclave_t.o \
		enclave.o enclave.so enclave.signed.so \
		enclave_u.h enclave_u.c enclave_u.o \
		support.o mainapp.o
clean:
	@rm -rf $(TRASH)
	$(call EVIL,,"[   RM   ] ",$(TRASH))
