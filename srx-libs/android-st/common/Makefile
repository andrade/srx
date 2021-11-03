CC := gcc

#TODO  Isto devia estar vazio por omissão, e neste caso é feito um teste para usar system default. Caso seja incompatível avisar, ou então deixar rebentar. Mas a variável existe caso alguém tenha uma versão instalada noutro local. Isto porque acontece algumas versões do SO não ter OpenSSL atual (como no meu caso).
SRX_OPENSSL ?= /home/daniel/tmp/openssl/openssl111a

CFLAGS := -m64 -Og -g -Wall -Wextra -std=c11 -fPIC -I./include \
		-I$(SRX_OPENSSL)/include
LDFLAGS := -fPIC -L. -L$(SRX_OPENSSL)/lib \
		-Wl,-rpath,$(SRX_OPENSSL)/lib,--disable-new-dtags
LDLIBS := -lcommon -lcrypto

SOURCES :=
HEADERS :=

HEADERS += $(wildcard include/srx/crypto/*.h)

SOURCES += $(wildcard crypto/*.c)
HEADERS += $(wildcard crypto/*.h)

OBJS := $(SOURCES:.c=.o)

TARGET := libcommon.a

all: $(TARGET)

$(TARGET): $(OBJS)
	ar rcs $@ $^

ex1: sample/ex1.c $(TARGET)
	gcc $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean

clean:
	rm -f $(OBJS)
	rm -f $(TARGET)
	rm -f ex1
