ACLOCAL_AMFLAGS = -I build-aux/m4

lib_LTLIBRARIES = libsecp256k1.la
if USE_JNI
JNI_LIB = libsecp256k1_jni.la
noinst_LTLIBRARIES = $(JNI_LIB)
else
JNI_LIB =
endif
include_HEADERS = include/secp256k1.h
noinst_HEADERS =
noinst_HEADERS += src/scalar.h
noinst_HEADERS += src/scalar_4x64.h
noinst_HEADERS += src/scalar_8x32.h
noinst_HEADERS += src/scalar_low.h
noinst_HEADERS += src/scalar_impl.h
noinst_HEADERS += src/scalar_4x64_impl.h
noinst_HEADERS += src/scalar_8x32_impl.h
noinst_HEADERS += src/scalar_low_impl.h
noinst_HEADERS += src/group.h
noinst_HEADERS += src/group_impl.h
noinst_HEADERS += src/num_gmp.h
noinst_HEADERS += src/num_gmp_impl.h
noinst_HEADERS += src/ecdsa.h
noinst_HEADERS += src/ecdsa_impl.h
noinst_HEADERS += src/eckey.h
noinst_HEADERS += src/eckey_impl.h
noinst_HEADERS += src/ecmult.h
noinst_HEADERS += src/ecmult_impl.h
noinst_HEADERS += src/ecmult_const.h
noinst_HEADERS += src/ecmult_const_impl.h
noinst_HEADERS += src/ecmult_gen.h
noinst_HEADERS += src/ecmult_gen_impl.h
noinst_HEADERS += src/num.h
noinst_HEADERS += src/num_impl.h
noinst_HEADERS += src/field_10x26.h
noinst_HEADERS += src/field_10x26_impl.h
noinst_HEADERS += src/field_5x52.h
noinst_HEADERS += src/field_5x52_impl.h
noinst_HEADERS += src/field_5x52_int128_impl.h
noinst_HEADERS += src/field_5x52_asm_impl.h
noinst_HEADERS += src/java/org_bitcoin_NativeSecp256k1.h
noinst_HEADERS += src/java/org_bitcoin_Secp256k1Context.h
noinst_HEADERS += src/util.h
noinst_HEADERS += src/scratch.h
noinst_HEADERS += src/scratch_impl.h
noinst_HEADERS += src/testrand.h
noinst_HEADERS += src/testrand_impl.h
noinst_HEADERS += src/hash.h
noinst_HEADERS += src/hash_impl.h
noinst_HEADERS += src/field.h
noinst_HEADERS += src/field_impl.h
noinst_HEADERS += src/bench.h
noinst_HEADERS += contrib/lax_der_parsing.h
noinst_HEADERS += contrib/lax_der_parsing.c
noinst_HEADERS += contrib/lax_der_privatekey_parsing.h
noinst_HEADERS += contrib/lax_der_privatekey_parsing.c

if USE_EXTERNAL_ASM
COMMON_LIB = libsecp256k1_common.la
noinst_LTLIBRARIES = $(COMMON_LIB)
else
COMMON_LIB =
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsecp256k1.pc

if ENABLE_SGX
SGX_SDK ?= /home/daniel/.local/lib/x86_64-linux-gnu/sgxsdk
SGX_SSL ?= /home/daniel/.local/lib/x86_64-linux-gnu/sgxssl
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
SGX_PRERELEASE ?= 0
SGX_EDGER8R ?= $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGN ?= $(SGX_SDK)/bin/x64/sgx_sign

$(info SGX_MODE=$(SGX_MODE))
$(info SGX_DEBUG=$(SGX_DEBUG))
$(info SGX_PRERELEASE=$(SGX_PRERELEASE))

BUILT_SOURCES =

ENCLAVE_CONFIG_FILE := enclave.config.xml

src/sgx/t/util.o: src/sgx/t/util.c
	@$(CC) -DSECP256K1_BUILD $(SGX_ENCLAVE_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

#TODO How to refer to this in non-libtool rules?
LIBSECP256K1_A = ./.libs/libsecp256k1.a
endif

if USE_EXTERNAL_ASM
if USE_ASM_ARM
libsecp256k1_common_la_SOURCES = src/asm/field_10x26_arm.s
endif
endif

libsecp256k1_la_SOURCES = src/secp256k1.c
libsecp256k1_la_CPPFLAGS = -DSECP256K1_BUILD -I$(top_srcdir)/include -I$(top_srcdir)/src $(SECP_INCLUDES)
libsecp256k1_la_LIBADD = $(JNI_LIB) $(SECP_LIBS) $(COMMON_LIB)
if ENABLE_SGX
####libsecp256k1_la_SOURCES += src/sgx_util.h src/sgx_util.c src/enclave_t.c src/enclave_t.h
####libsecp256k1_la_SOURCES += src/sgx/t/util.h src/sgx/t/util.c src/tests_t.c src/tests_t.h
######libsecp256k1_la_SOURCES += src/sgx/t/util.h src/sgx/t/util.c src/bench_verify_t.c src/bench_verify_t.h

#libsecp256k1_la_SOURCES += src/sgx/t/util.h src/sgx/t/util.c
####libsecp256k1_la_CFLAGS = -I$(SGX_SDK)/include/tlibc -I$(SGX_SSL)/include -nostdinc -nostdlib -fPIC
#libsecp256k1_la_CFLAGS = $(SGX_ENCLAVE_CFLAGS)

#libsecp256k1_la_CPPFLAGS += -nostdinc \
#		-I$SGX_SDK/include/tlibc -I$SGX_SSL/include
#libsecp256k1_la_CFLAGS = -fPIC
#libsecp256k1_la_LDFLAGS = -nostdlib -nodefaultlibs -L$(SGX_SDK)/lib64 -L$(SGX_SSL)/lib64/debug
#libsecp256k1_la_LIBADD += $(SGX_ENCLAVE_LDLIBS)

libsecp256k1_la_CPPFLAGS += -nostdinc -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SSL)/include
libsecp256k1_la_CFLAGS = -fPIC #$(SGX_ENCLAVE_CFLAGS)
#libsecp256k1_la_CPPFLAGS += $(SGX_ENCLAVE_CPPFLAGS)
#libsecp256k1_la_CFLAGS = -fPIC $(SGX_ENCLAVE_CFLAGS)
#libsecp256k1_la_LDFLAGS = $(SGX_ENCLAVE_LDFLAGS)
####libsecp256k1_la_LDFLAGS = -static
#libsecp256k1_la_LIBADD += $(SGX_ENCLAVE_LDLIBS)
endif

libsecp256k1_jni_la_SOURCES  = src/java/org_bitcoin_NativeSecp256k1.c src/java/org_bitcoin_Secp256k1Context.c
libsecp256k1_jni_la_CPPFLAGS = -DSECP256K1_BUILD $(JNI_INCLUDES)

noinst_PROGRAMS =
if USE_BENCHMARK
include src/bench.mk
endif

TESTS =
if USE_TESTS
include src/tests.mk
endif

if USE_EXHAUSTIVE_TESTS
include src/tests_exhaustive.mk
endif

JAVAROOT=src/java
JAVAORG=org/bitcoin
JAVA_GUAVA=$(srcdir)/$(JAVAROOT)/guava/guava-18.0.jar
CLASSPATH_ENV=CLASSPATH=$(JAVA_GUAVA)
JAVA_FILES= \
  $(JAVAROOT)/$(JAVAORG)/NativeSecp256k1.java \
  $(JAVAROOT)/$(JAVAORG)/NativeSecp256k1Test.java \
  $(JAVAROOT)/$(JAVAORG)/NativeSecp256k1Util.java \
  $(JAVAROOT)/$(JAVAORG)/Secp256k1Context.java

if USE_JNI

$(JAVA_GUAVA):
	@echo Guava is missing. Fetch it via: \
	wget https://search.maven.org/remotecontent?filepath=com/google/guava/guava/18.0/guava-18.0.jar -O $(@)
	@false

.stamp-java: $(JAVA_FILES)
	@echo   Compiling $^
	$(AM_V_at)$(CLASSPATH_ENV) javac $^
	@touch $@

if USE_TESTS

check-java: libsecp256k1.la $(JAVA_GUAVA) .stamp-java
	$(AM_V_at)java -Djava.library.path="./:./src:./src/.libs:.libs/" -cp "$(JAVA_GUAVA):$(JAVAROOT)" $(JAVAORG)/NativeSecp256k1Test

endif
endif

if USE_ECMULT_STATIC_PRECOMPUTATION
CPPFLAGS_FOR_BUILD +=-I$(top_srcdir)
CFLAGS_FOR_BUILD += -Wall -Wextra -Wno-unused-function

gen_context_OBJECTS = gen_context.o
gen_context_BIN = gen_context$(BUILD_EXEEXT)
gen_%.o: src/gen_%.c
	$(CC_FOR_BUILD) $(CPPFLAGS_FOR_BUILD) $(CFLAGS_FOR_BUILD) -c $< -o $@

$(gen_context_BIN): $(gen_context_OBJECTS)
	$(CC_FOR_BUILD) $^ -o $@

$(libsecp256k1_la_OBJECTS): src/ecmult_static_context.h
$(tests_OBJECTS): src/ecmult_static_context.h
$(bench_internal_OBJECTS): src/ecmult_static_context.h
$(bench_ecmult_OBJECTS): src/ecmult_static_context.h

src/ecmult_static_context.h: $(gen_context_BIN)
	./$(gen_context_BIN)

CLEANFILES = $(gen_context_BIN) src/ecmult_static_context.h $(JAVAROOT)/$(JAVAORG)/*.class .stamp-java
endif

EXTRA_DIST = autogen.sh src/gen_context.c src/basic-config.h $(JAVA_FILES)

if ENABLE_MODULE_ECDH
include src/modules/ecdh/Makefile.am.include
endif

if ENABLE_MODULE_RECOVERY
include src/modules/recovery/Makefile.am.include
endif

print-%  : ; @echo $* = $($*)
