CC := gcc
EDGER := sgx_edger8r

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
SGX_SSL ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxssl
$(info [ SGX_DIR] "$(SGX_SDK)")
$(info [ SGX_DIR] "$(SGX_SSL)")

SRX_API ?=
ifndef SRX_API
$(error SRX_API is not set)
endif

SGX_DEBUG ?= 1
SGX_PRERELEASE ?= 0
SRX_DEBUG ?= 1
PLATFORM_ID ?= 0

# Print the correct verification code when enabled (development only)
SRX_DEBUG_PRINT_VERIFICATION_CODE ?= 1
SRX_DEBUG_AUTOFILL ?= 0

RLOG ?= RLOG_TRACE

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

CFLAGS := -DRLOG=$(RLOG) -m64 -Wall -Wextra -I$(SRX_USGX)/include \
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

ifeq ($(SRX_DEBUG),1)
ifneq ($(PLATFORM_ID),0)
	CFLAGS += -DSRX_PLATFORM_ID=$(PLATFORM_ID)    # simulate diff platform
endif
	undefine PLATFORM_ID
ifeq ($(SRX_DEBUG_PRINT_VERIFICATION_CODE),1)
	CFLAGS += -DSRX_DEBUG_PRINT_VERIFICATION_CODE
else
	CFLAGS += -USRX_DEBUG_PRINT_VERIFICATION_CODE
endif
ifeq ($(SRX_DEBUG_AUTOFILL),1)
	CFLAGS += -DSRX_DEBUG_AUTOFILL
else
	CFLAGS += -USRX_DEBUG_AUTOFILL
endif
endif

TLIB_IPATHS := -I. \
		-I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
		-I$(SGX_SDK)/include/epid -I$(SGX_SSL)/include \
		-I$(SRX_PROTOCOL) -I$(SRX_PROTOCOL)/linux -I$(SRX_PROTOCOL)/asn1c -I$(SRX_PROTOCOL)/sgx -D ENABLE_ENCLAVE_ASNONE_CODE=1
TLIB_CFLAGS := $(CFLAGS) -std=c11 -fPIC \
		-Wno-implicit-function-declaration -nostdinc -fpie -fstack-protector \
		-fno-builtin-printf $(TLIB_IPATHS)

ULIB_IPATHS := -I$(SGX_SDK)/include -I.
ULIB_CFLAGS := $(CFLAGS) -std=c11 \
		`pkg-config --cflags gtk+-3.0` \
		-fPIC -Wno-attributes $(ULIB_IPATHS)

all: libpst-client.a libpst-client-untrusted.a
	@echo "MAKE  ·  $^"

# Trusted code

srx_t.c: $(SRX_API)/srx.edl
	@$(EDGER) --trusted $< --trusted-dir . --search-path $(SGX_SDK)/include
	@echo "GEN   ·  $^  >  $@"

srx_t.o: srx_t.c
	@$(CC) $(TLIB_IPATHS) $(TLIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

bincat.o: bincat.c bincat.h

crypto.o: crypto.c

ds.o: ds.c ds.h

#protocol.o: protocol.c

rp.o: rp.c rp.h

storage.o: storage.c storage.h ds.h

token.o: token.c

util.o: util.c util.h

st/device.o: st/device.c st/device.h

st/protocol.o: st/protocol.c st/protocol.h

tconst.o: tconst.c tconst.h

# protocol.o
CLIENT_SECURE_OBJS := bincat.o crypto.o ds.o rp.o storage.o token.o util.o st/device.o st/protocol.o tconst.o

$(CLIENT_SECURE_OBJS):
	@$(CC) $(TLIB_IPATHS) $(TLIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

#%.o: %.c
#	@$(CC) $(TLIB_IPATHS) $(TLIB_CFLAGS) -c $< -o $@
#	@echo "CC    ·  $^  >  $@"

## generate headers before compiling server sources
#token.o: protocol/libasn1.a
#
#protocol/libasn1.a:
#	$(MAKE) -C protocol validate
#	$(MAKE) -C protocol generate
#	$(MAKE) -C protocol
#
#libpst-client.a: protocol/libasn1.a

libpst-client.a: srx_t.o $(CLIENT_SECURE_OBJS)
	@ar rcs $@ $^
	$(call GOOD,,"GEN   ·  ","$^  >  $@")

# Untrusted code

srx_u.c: $(SRX_API)/srx.edl
	@$(EDGER) --untrusted $< --untrusted-dir . --search-path $(SGX_SDK)/include
	@echo "GEN   ·  $^  >  $@"

srx_u.o: srx_u.c
	@$(CC) $(ULIB_IPATHS) $(ULIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

%.o: %.c srx_u.h
	@$(CC) $(ULIB_IPATHS) $(ULIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

untrusted.o: untrusted.c srx_u.h
	@$(CC) $(ULIB_IPATHS) $(ULIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

ctio/%.o: ctio/%.c
	@$(CC) $(ULIB_IPATHS) $(ULIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

libpst-client-untrusted.a: srx_u.o untrusted.o ctio/ctio.o ctio/qrc.o ctio/gui.o
	@ar rcs $@ $^
	$(call GOOD,,"GEN   ·  ","$^  >  $@")

# Maintenance

TRASH := \
		srx_t.h srx_t.c srx_t.o \
		$(CLIENT_SECURE_OBJS) \
		libpst-client.a \
		srx_u.h srx_u.c srx_u.o untrusted.o libpst-client-untrusted.a \
		ctio/*.o
.PHONY: clean
clean:
	@rm -rf $(TRASH)
#$(MAKE) -C protocol clean && rm --force protocol/*.h protocol/*.c
	$(call EVIL,"CLEAN ·  Remove: ",$(TRASH),)
