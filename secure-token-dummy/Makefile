CC := gcc
EDGER := sgx_edger8r

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
$(info [SGX_SDK ] "$(SGX_SDK)")

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

CFLAGS := -m64 -Og -g -Wall -Wextra

TLIB_IPATHS := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
		-I$(SGX_SDK)/include/epid
TLIB_CFLAGS := $(CFLAGS) -std=c11 \
		-Wno-implicit-function-declaration -nostdinc -fpie -fstack-protector \
		-fno-builtin-printf $(TLIB_IPATHS) \
		-DDEBUG

all: libdummy.a
	@echo "MAKE  ·  $^"

srx_t.c: ../secure-token-api/srx.edl
	@$(EDGER) --trusted $< --trusted-dir .
	@echo "GEN   ·  $^  >  $@"

srx_t.o: srx_t.c
	@$(CC) $(TLIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

%.o: %.c
	@$(CC) $(TLIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

libdummy.a: srx_t.o dummy.o
	@ar rcs $@ $^
	$(call GOOD,,"GEN   ·  ","$^  >  $@")

# Maintenance

TRASH := srx_t.h srx_t.c srx_t.o dummy.o libdummy.a
.PHONY: clean
clean:
	@rm -rf $(TRASH)
	$(call EVIL,"CLEAN ·  Remove: ",$(TRASH),)
