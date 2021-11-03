ACLOCAL_AMFLAGS = -I build-aux/m4
.PHONY: gen
.INTERMEDIATE: $(GENBIN)

if WITH_SGX
SGX_SDK ?= /home/daniel/.local/lib/x86_64-linux-gnu/sgxsdk
SGX_SSL ?= /home/daniel/.local/lib/x86_64-linux-gnu/sgxssl
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
SGX_PRERELEASE ?= 0
SGX_EDGER8R ?= $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGN ?= $(SGX_SDK)/bin/x64/sgx_sign

$(info SGX_MODE=$(SGX_MODE))

BUILT_SOURCES =

ENCLAVE_CONFIG_FILE := enclave.config.xml

#TODO How to refer to this in non-libtool rules?
LIBSECP256K1_A = $(top_srcdir)/src/secp256k1/.libs/libsecp256k1.a
endif

DIST_SUBDIRS = src/secp256k1

LIBSECP256K1=src/secp256k1/libsecp256k1.la

#FIXME hack para conseguir compilar com ".a"... devia usar o ".la"
if !WITH_SGX
$(LIBSECP256K1): $(wildcard src/secp256k1/src/*) $(wildcard src/secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
$(LIBSECP256K1_A): $(wildcard src/secp256k1/src/*) $(wildcard src/secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C src/secp256k1 libsecp256k1.la
endif

lib_LTLIBRARIES = libbtc.la
include_HEADERS = \
    include/btc/aes256_cbc.h \
    include/btc/base58.h \
    include/btc/bip32.h \
    include/btc/block.h \
    include/btc/btc.h \
    include/btc/buffer.h \
    include/btc/chainparams.h \
    include/btc/cstr.h \
    include/btc/ctaes.h \
    include/btc/ecc_key.h \
    include/btc/ecc.h \
    include/btc/hash.h \
    include/btc/portable_endian.h \
    include/btc/random.h \
    include/btc/script.h \
    include/btc/segwit_addr.h \
    include/btc/serialize.h \
    include/btc/sha2.h \
    include/btc/tool.h \
    include/btc/tx.h \
    include/btc/utils.h \
    include/btc/vector.h

noinst_HEADERS = \
	src/ripemd160.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libbtc.pc

libbtc_la_SOURCES = \
    src/aes256_cbc.c \
    src/base58.c \
    src/bip32.c \
    src/block.c \
    src/buffer.c \
    src/chainparams.c \
    src/commontools.c \
    src/cstr.c \
    src/ctaes.c \
    src/ecc_key.c \
    src/ecc_libsecp256k1.c \
    src/memory.c \
    src/memory.h \
    src/random.c \
    src/ripemd160.c \
    src/script.c \
    src/segwit_addr.c \
    src/serialize.c \
    src/sha2.c \
    src/tx.c \
    src/utils.c \
    src/vector.c

libbtc_la_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src/logdb/include
if !WITH_SGX
libbtc_la_LIBADD = $(LIBSECP256K1)
else
libbtc_la_LIBADD = $(LIBSECP256K1_A)
endif

if WITH_SGX
libbtc_la_CPPFLAGS = $(SGX_ENC_CPPFLAGS)
libbtc_la_CFLAGS += $(SGX_ENC_CFLAGS) -fPIC
libbtc_la_LDFLAGS = $(SGX_ENC_LDFLAGS) -static
endif

if USE_TESTS
noinst_PROGRAMS = tests
if !WITH_SGX
tests_LDADD = libbtc.la
tests_SOURCES = \
    test/aes_tests.c \
    test/base58check_tests.c \
    test/bip32_tests.c \
    test/block_tests.c \
    test/buffer_tests.c \
    test/cstr_tests.c \
    test/ecc_tests.c \
    test/eckey_tests.c \
    test/hash_tests.c \
    test/memory_tests.c \
    test/random_tests.c \
    test/serialize_tests.c \
    test/sha2_tests.c \
    test/utest.h \
    test/unittester.c \
    test/tx_tests.c \
    test/utils_tests.c \
    test/vector_tests.c

tests_CFLAGS = $(libbtc_la_CFLAGS)
tests_CPPFLAGS = -I$(top_srcdir)/src
tests_LDFLAGS = -static
else
# begin: tests basic stuff (first part)
tests_SOURCES = test/unittester_bootstrap.c src/sgx.h
tests_CPPFLAGS = -I$(top_srcdir)/src
tests_CFLAGS =
tests_LDFLAGS =
tests_LDADD =
# end: tests basic stuff (first part)

# new trusted lib for tests
noinst_LIBRARIES = libbtc_tests.a
libbtc_tests_a_SOURCES = \
    test/aes_tests.c \
    test/base58check_tests.c \
    test/bip32_tests.c \
    test/block_tests.c \
    test/buffer_tests.c \
    test/cstr_tests.c \
    test/ecc_tests.c \
    test/eckey_tests.c \
    test/hash_tests.c \
    test/memory_tests.c \
    test/random_tests.c \
    test/serialize_tests.c \
    test/sha2_tests.c \
    test/utest.h \
    test/unittester.c \
    test/tx_tests.c \
    test/utils_tests.c \
    test/vector_tests.c

libbtc_tests_a_LIBADD = libbtc.la
libbtc_tests_a_CFLAGS = $(libbtc_la_CFLAGS) $(SGX_ENC_CFLAGS)
libbtc_tests_a_CPPFLAGS = -I$(top_srcdir)/src $(SGX_ENC_CPPFLAGS)
libbtc_tests_a_LDFLAGS = $(SGX_ENC_LDFLAGS)
#

# begin: make .so
##TODO can I have a file to automate this? ideally using autotools-foo..
UNITTESTER_ENCLAVE := unittester.enclave.so
UNITTESTER_ESIGNED := unittester.enclave.signed.so
# how to libtoolize building this stuff w/ SGX (mix .a .la etc)?

LIBBTC_A = $(top_srcdir)/.libs/libbtc.a

#FIXME shouldn't be here, why not generated on demand as it should?
BUILT_SOURCES += \
    test/unittester_u.c \
    test/unittester_u.h \
    test/unittester_t.c \
    test/unittester_t.h

test/unittester_u.c test/unittester_u.h: $(SGX_EDGER8R) test/unittester.edl
	@cd test && $(SGX_EDGER8R) \
			--untrusted unittester.edl \
			--search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"
# --search-path $(SGX_SSL)/include

test/unittester_u.o: test/unittester_u.c test/unittester_u.h
	@$(CC) $(SGX_APP_CPPFLAGS) $(SGX_APP_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

test/unittester_t.c test/unittester_t.h: $(SGX_EDGER8R) test/unittester.edl
	@cd test && $(SGX_EDGER8R) \
			--trusted unittester.edl \
			--search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"
#--search-path $(top_srcdir)/test \
# --search-path $(SGX_SSL)/include

test/unittester_t.o: test/unittester_t.c test/unittester_t.h
	@$(CC) $(SGX_ENC_CPPFLAGS) $(SGX_ENC_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

test/unittester.o: test/unittester.c test/unittester_u.h
	@$(CC) $(SGX_ENC_CPPFLAGS) $(SGX_ENC_CFLAGS) -DHAVE_CONFIG_H \
			-I$(top_srcdir)/test -I$(top_srcdir)/include \
			-c $< -o $@
	@echo "CC   <=  $<"
#-DSECP256K1_BUILD -DVERIFY -I. -I./test \
#$(SECP_INCLUDES) $(SECP_TEST_INCLUDES) \
#-I/usr/include/x86_64-linux-gnu/ \
#
#	@$(CXX) $(SGX_ENC_CXXFLAGS) $(DEFS) -DSECP256K1_BUILD -I$(top_srcdir) -I$(top_srcdir)/src -I$(top_srcdir)/include $(SECP_INCLUDES) $(SECP_TEST_INCLUDES) -c $< -o $@

UNITTESTER_ENCLAVE_OBJS = test/unittester_t.o test/unittester.o
test/$(UNITTESTER_ENCLAVE): $(UNITTESTER_ENCLAVE_OBJS) libbtc_tests.a $(LIBBTC_A) $(LIBSECP256K1_A)
	$(CC) $(SGX_ENC_CPPFLAGS) -I$(top_srcdir)/src/secp256k1/include $(SGX_ENC_CFLAGS) $(SGX_ENC_LDFLAGS) $^ -o  $@ $(SGX_ENC_LDLIBS)
	@echo "LINK =>  $@"
#	$(LIBTOOL) --mode=link $(CXX) $(SGX_ENC_LDFLAGS) $^ -o  $@ $(SGX_ENC_LDLIBS)
#src/$(ENCLAVE_NAME): src/enclave_t.o src/enclave.o src/tests.o $(lib_LTLIBRARIES)
#	$(CXX) $^ -I$(top_srcdir)/include -I$(top_srcdir)/contrib -I$(top_srcdir)/src $(SECP_INCLUDES) -o  $@ $(SGX_ENC_LDFLAGS) $(SGX_ENC_LDLIBS) \
#		$(JNI_LIB) $(SECP_LIBS) $(COMMON_LIB)
#	@echo "LINK =>  $@"

test/$(UNITTESTER_ESIGNED): test/$(UNITTESTER_ENCLAVE) $(SGX_KEY)
	@cd test && $(SGX_SIGN) sign \
			-key $(SGX_KEY) \
			-enclave $(UNITTESTER_ENCLAVE) \
			-out $(UNITTESTER_ESIGNED) \
			-config $(ENCLAVE_CONFIG_FILE)
# end: make.so

tests_SOURCES += test/unittester_u.c test/unittester_u.h
tests_CPPFLAGS += $(SGX_APP_CPPFLAGS)
tests_CFLAGS += $(SGX_APP_CFLAGS)
tests_LDFLAGS += $(SGX_APP_LDFLAGS)
tests_LDADD += $(SGX_APP_LDLIBS) test/$(UNITTESTER_ESIGNED)
endif
TESTS = tests
endif

if WITH_WALLET

libbtc_la_SOURCES += \
    src/logdb/logdb_core.c \
    src/logdb/logdb_memdb_llist.c \
    src/logdb/logdb_memdb_rbtree.c \
    src/logdb/logdb_rec.c \
    src/logdb/red_black_tree.c

include_HEADERS += \
    src/logdb/include/logdb/logdb_base.h \
    src/logdb/include/logdb/logdb_core.h \
    src/logdb/include/logdb/logdb_memdb_llist.h \
    src/logdb/include/logdb/logdb_memdb_rbtree.h \
    src/logdb/include/logdb/logdb_rec.h \
    src/logdb/include/logdb/logdb.h \
    src/logdb/include/logdb/red_black_tree.h

include_HEADERS += \
    include/btc/wallet.h

libbtc_la_SOURCES += \
    src/wallet.c

if USE_TESTS
tests_SOURCES += \
    test/wallet_tests.c \
    src/logdb/test/logdb_tests.c \
    src/logdb/test/tests_red_black_tree.c
endif
endif

if WITH_NET
include_HEADERS += \
    include/btc/headersdb.h \
    include/btc/headersdb_file.h \
    include/btc/protocol.h \
    include/btc/net.h \
    include/btc/netspv.h

libbtc_la_SOURCES += \
    src/headersdb_file.c \
    src/net.c \
    src/netspv.c \
    src/protocol.c

libbtc_la_LIBADD += $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)
libbtc_la_CFLAGS += $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)

if USE_TESTS
tests_SOURCES += \
    test/net_tests.c \
    test/netspv_tests.c \
    test/protocol_tests.c
tests_LDADD += $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)
tests_LDFLAGS += -levent
endif
endif

if WITH_TOOLS
if USE_TESTS
tests_SOURCES += \
    test/tool_tests.c
endif
instdir=$(prefix)/bin
inst_PROGRAMS = bitcointool
bitcointool_LDADD = libbtc.la
bitcointool_SOURCES = \
    src/tools/bitcointool.c
bitcointool_CFLAGS = $(libbtc_la_CFLAGS)
bitcointool_CPPFLAGS = -I$(top_srcdir)/src
bitcointool_LDFLAGS = -static

if WITH_NET
inst_PROGRAMS += bitcoin-send-tx
bitcoin_send_tx_LDADD = libbtc.la $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)
bitcoin_send_tx_SOURCES = \
    src/tools/bitcoin-send-tx.c
bitcoin_send_tx_CFLAGS = $(libbtc_la_CFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
bitcoin_send_tx_CPPFLAGS = -I$(top_srcdir)/src
bitcoin_send_tx_LDFLAGS = -static

inst_PROGRAMS += bitcoin-spv
bitcoin_spv_LDADD = libbtc.la
bitcoin_spv_SOURCES = \
    src/tools/bitcoin-spv.c
bitcoin_spv_CFLAGS = $(libbtc_la_CFLAGS)
bitcoin_spv_CPPFLAGS = -I$(top_srcdir)/src
bitcoin_spv_LDFLAGS = -static
endif

endif

clean-local:
	-$(MAKE) -C src/secp256k1 clean

# temp para debug
print-%  : ; @echo $* = $($*)
