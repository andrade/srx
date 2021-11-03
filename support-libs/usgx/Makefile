CC := gcc
EDGER := sgx_edger8r

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
$(info [SGX_SDK ] "$(SGX_SDK)")

SGX_DEBUG ?= 1
$(info [SGX_DEBUG] "$(SGX_DEBUG)")

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

CPPFLAGS := -I./include
CFLAGS := -m64 -Wall -Wextra -std=c11

ifeq ($(SGX_DEBUG),1)
	CFLAGS += -Og -g
	CFLAGS += -DDEBUG
else
	CFLAGS += -O2
	CFLAGS += -UDEBUG
endif

TLIB_IPATHS := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
		-I$(SGX_SDK)/include/epid
TLIB_CFLAGS := $(CPPFLAGS) $(CFLAGS) \
		-Wno-implicit-function-declaration -nostdinc -fpie -fstack-protector \
		-fno-builtin-printf $(TLIB_IPATHS)

ULIB_CFLAGS := $(CPPFLAGS) $(CFLAGS) -I$(SGX_SDK)/include -fPIC -Wno-attributes

all: libusgx-normal.a libusgx-secure.a
	@echo "MAKE  ·  $^"

#                           UNTRUSTED                           #

src/u/util_u.c src/u/util_u.h: include/usgx/util.edl
	@$(EDGER) --untrusted $< --untrusted-dir src/u
	@echo "GEN   ·  $^  >  $@"

src/u/util.o: src/u/util_u.h

src/u/%.o: src/u/%.c
	@$(CC) $(ULIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

libusgx-normal.a: src/u/util.o src/u/util_u.o
	@ar rcs $@ $^
	$(call GOOD,,"GEN   ·  ","$^  >  $@")

#                            TRUSTED                            #

src/t/util_t.c src/t/util_t.h: include/usgx/util.edl
	@$(EDGER) --trusted $< --trusted-dir src/t
	@echo "GEN   ·  $^  >  $@"

src/t/util.o: src/t/util_t.h

src/t/%.o: src/t/%.c
	@$(CC) $(TLIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

libusgx-secure.a: src/t/util.o src/t/util_t.o
	@ar rcs $@ $^
	$(call GOOD,,"GEN   ·  ","$^  >  $@")

#                          MAINTENANCE                          #

.PHONY: clean

TRASH := \
		src/u/util_u.h src/u/util_u.c src/u/util_u.o \
		src/u/util.o \
		libusgx-normal.a \
		src/t/util_t.h src/t/util_t.c src/t/util_t.o \
		src/t/util.o \
		libusgx-secure.a

clean:
	@rm -rf $(TRASH)
	$(call EVIL,"CLEAN ·  Remove: ",$(TRASH),)
