CC := gcc

SRX_OPENSSL ?=

ifndef SRX_OPENSSL
$(error Environment variable `SRX_OPENSSL` is not set)
endif
$(info [SRX_OPENSSL] "$(SRX_OPENSSL)")

#-Iprotocol -Iprotocol/asn1c -Iprotocol/linux -Iprotocol/sgx
override CPPFLAGS += -I. -Iinclude \
		-I$(SRX_PROTOCOL) -I$(SRX_PROTOCOL)/asn1c -I$(SRX_PROTOCOL)/linux \
		-I$(SRX_COMMON_INC) \
		-I$(FOOSSL_INCLUDE) \
		-I$(SRX_OPENSSL)/include
override CFLAGS += -m64 -Og -g -Wall -Wextra -std=c11 -fPIC
LDFLAGS := -fPIC -L. \
		-L$(SRX_COMMON_LIB) \
		-L$(FOOSSL_LIBRARY) \
		-L$(SRX_PROTOCOL) \
		-L$(SRX_OPENSSL)/lib -Wl,-rpath,$(SRX_OPENSSL)/lib,--disable-new-dtags
LDLIBS := \
		-lcommon \
		-lfoossl_server -lfoossl_common \
		-lasn1proto-normal \
		-lssl -lcrypto \
		-lconfig

SOURCES :=
#HEADERS :=

#HEADERS += $(wildcard include/srx/crypto/*.h)

#HEADERS += $(wildcard protocol/*.h)
#HEADERS += $(wildcard protocol/asn1c/*.h)
#HEADERS += $(wildcard protocol/linux/*.h)
#HEADERS += $(wildcard protocol/sgx/*.h)

#SOURCES += $(wildcard crypto/*.c)
#HEADERS += $(wildcard crypto/*.h)

SOURCES += $(wildcard *.c)

OBJS := $(SOURCES:.c=.o)

TARGET := server

all: $(TARGET)

# generate headers before compiling server sources
#server.o: protocol/libasn1.a

#protocol/libasn1.a:
#	$(MAKE) -C protocol validate
#	$(MAKE) -C protocol generate
#	$(MAKE) -C protocol

#$(TARGET): protocol/libasn1.a

$(TARGET): $(OBJS)
	gcc $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean

clean:
	rm -f $(OBJS)
	rm -f $(TARGET)
#$(MAKE) -C protocol clean && rm --force protocol/*.h protocol/*.c
