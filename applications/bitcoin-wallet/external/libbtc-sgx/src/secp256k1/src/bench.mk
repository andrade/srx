noinst_PROGRAMS += bench_verify bench_sign bench_internal bench_ecmult
bench_verify_SOURCES = src/bench_verify_bootstrap.c
bench_verify_LDADD = $(SECP_LIBS) $(SECP_TEST_LIBS) $(COMMON_LIB)
bench_sign_SOURCES = src/bench_sign_bootstrap.c
bench_sign_LDADD = $(SECP_LIBS) $(SECP_TEST_LIBS) $(COMMON_LIB)
bench_internal_SOURCES = src/bench_internal_bootstrap.c
bench_internal_LDADD = $(SECP_LIBS) $(COMMON_LIB)
bench_internal_CPPFLAGS = -DSECP256K1_BUILD $(SECP_INCLUDES)
bench_ecmult_SOURCES = src/bench_ecmult_bootstrap.c
bench_ecmult_LDADD = $(SECP_LIBS) $(COMMON_LIB)
bench_ecmult_CPPFLAGS = -DSECP256K1_BUILD $(SECP_INCLUDES)
if !ENABLE_SGX
bench_verify_SOURCES += src/bench_verify.c
bench_verify_LDADD += libsecp256k1.la
bench_sign_SOURCES += src/bench_sign.c
bench_sign_LDADD += libsecp256k1.la
bench_internal_SOURCES += src/bench_internal.c
bench_ecmult_SOURCES += src/bench_ecmult.c
else
BENCH_VERIFY_ENCLAVE := bench_verify.enclave.so
BENCH_VERIFY_ESIGNED := bench_verify.enclave.signed.so

BUILT_SOURCES += src/bench_verify_u.c src/bench_verify_u.h src/bench_verify_t.c src/bench_verify_t.h

src/bench_verify_u.c src/bench_verify_u.h: $(SGX_EDGER8R) src/bench_verify.edl
	@cd src && $(SGX_EDGER8R) --untrusted bench_verify.edl \
			--search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

src/bench_verify_u.o: src/bench_verify_u.c src/bench_verify_u.h
	@$(CC) $(SGX_APP_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

src/bench_verify_t.c src/bench_verify_t.h: $(SGX_EDGER8R) src/bench_verify.edl
	@cd src && $(SGX_EDGER8R) --trusted bench_verify.edl \
			--search-path $(top_srcdir)/src \
			--search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

src/bench_verify_t.o: src/bench_verify_t.c src/bench_verify_t.h
	@$(CC) $(SGX_ENCLAVE_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

src/bench_verify.o: src/bench_verify.c
	@$(CC) $(SGX_ENCLAVE_CFLAGS) -DHAVE_CONFIG_H \
			-DSECP256K1_BUILD -DVERIFY -I. -I./src -I$(top_srcdir)/src -I$(top_srcdir)/include \
			$(SECP_INCLUDES) $(SECP_TEST_INCLUDES) \
			-I/usr/include/x86_64-linux-gnu/ \
			-c $< -o $@
	@echo "CC   <=  $<"

BENCH_VERIFY_ENCLAVE_OBJS = src/sgx/t/util.o \
		src/bench_verify_t.o src/bench_verify.o

src/$(BENCH_VERIFY_ENCLAVE): $(BENCH_VERIFY_ENCLAVE_OBJS) $(LIBSECP256K1_A)
	$(CXX) $(SGX_ENCLAVE_CXXFLAGS) $(SGX_ENCLAVE_LDFLAGS) $^ -o  $@ $(SGX_ENCLAVE_LDLIBS)
	@echo "LINK =>  $@"

src/$(BENCH_VERIFY_ESIGNED): src/$(BENCH_VERIFY_ENCLAVE) $(SGX_KEY)
	@cd src && $(SGX_SIGN) sign -key $(SGX_KEY) \
			-enclave $(BENCH_VERIFY_ENCLAVE) -out $(BENCH_VERIFY_ESIGNED) \
			-config $(ENCLAVE_CONFIG_FILE)
	@echo "SIGN =>  $@"

BENCH_SIGN_ENCLAVE := bench_sign.enclave.so
BENCH_SIGN_ESIGNED := bench_sign.enclave.signed.so

BUILT_SOURCES += src/bench_sign_u.c src/bench_sign_u.h src/bench_sign_t.c src/bench_sign_t.h

src/bench_sign_u.c src/bench_sign_u.h: $(SGX_EDGER8R) src/bench_sign.edl
	@cd src && $(SGX_EDGER8R) --untrusted bench_sign.edl \
			--search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

src/bench_sign_u.o: src/bench_sign_u.c src/bench_sign_u.h
	@$(CC) $(SGX_APP_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

src/bench_sign_t.c src/bench_sign_t.h: $(SGX_EDGER8R) src/bench_sign.edl
	@cd src && $(SGX_EDGER8R) --trusted bench_sign.edl \
			--search-path $(top_srcdir)/src \
			--search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

src/bench_sign_t.o: src/bench_sign_t.c src/bench_sign_t.h
	@$(CC) $(SGX_ENCLAVE_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

src/bench_sign.o: src/bench_sign.c
	@$(CC) $(SGX_ENCLAVE_CFLAGS) -DHAVE_CONFIG_H \
			-DSECP256K1_BUILD -DVERIFY -I. -I./src -I$(top_srcdir)/src -I$(top_srcdir)/include \
			$(SECP_INCLUDES) $(SECP_TEST_INCLUDES) \
			-I/usr/include/x86_64-linux-gnu/ \
			-c $< -o $@
	@echo "CC   <=  $<"

BENCH_SIGN_ENCLAVE_OBJS = src/sgx/t/util.o \
		src/bench_sign_t.o src/bench_sign.o

src/$(BENCH_SIGN_ENCLAVE): $(BENCH_SIGN_ENCLAVE_OBJS) $(LIBSECP256K1_A)
	$(CXX) $(SGX_ENCLAVE_CXXFLAGS) $(SGX_ENCLAVE_LDFLAGS) $^ -o  $@ $(SGX_ENCLAVE_LDLIBS)
	@echo "LINK =>  $@"

src/$(BENCH_SIGN_ESIGNED): src/$(BENCH_SIGN_ENCLAVE) $(SGX_KEY)
	@cd src && $(SGX_SIGN) sign -key $(SGX_KEY) \
			-enclave $(BENCH_SIGN_ENCLAVE) -out $(BENCH_SIGN_ESIGNED) \
			-config $(ENCLAVE_CONFIG_FILE)
	@echo "SIGN =>  $@"

BENCH_INTERNAL_ENCLAVE := bench_internal.enclave.so
BENCH_INTERNAL_ESIGNED := bench_internal.enclave.signed.so

BUILT_SOURCES += src/bench_internal_u.c src/bench_internal_u.h src/bench_internal_t.c src/bench_internal_t.h

src/bench_internal_u.c src/bench_internal_u.h: $(SGX_EDGER8R) src/bench_internal.edl
	@cd src && $(SGX_EDGER8R) --untrusted bench_internal.edl \
			--search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

src/bench_internal_u.o: src/bench_internal_u.c src/bench_internal_u.h
	@$(CC) $(SGX_APP_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

src/bench_internal_t.c src/bench_internal_t.h: $(SGX_EDGER8R) src/bench_internal.edl
	@cd src && $(SGX_EDGER8R) --trusted bench_internal.edl \
			--search-path $(top_srcdir)/src \
			--search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

src/bench_internal_t.o: src/bench_internal_t.c src/bench_internal_t.h
	@$(CC) $(SGX_ENCLAVE_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

src/bench_internal.o: src/bench_internal.c
	@$(CC) $(SGX_ENCLAVE_CFLAGS) -DHAVE_CONFIG_H \
			-DSECP256K1_BUILD -DVERIFY -I. -I./src -I$(top_srcdir)/src -I$(top_srcdir)/include \
			$(SECP_INCLUDES) $(SECP_TEST_INCLUDES) \
			-I/usr/include/x86_64-linux-gnu/ \
			-c $< -o $@
	@echo "CC   <=  $<"

BENCH_INTERNAL_ENCLAVE_OBJS = src/sgx/t/util.o \
		src/bench_internal_t.o src/bench_internal.o

src/$(BENCH_INTERNAL_ENCLAVE): $(BENCH_INTERNAL_ENCLAVE_OBJS)
	$(CXX) $(SGX_ENCLAVE_CXXFLAGS) $(SGX_ENCLAVE_LDFLAGS) $^ -o  $@ $(SGX_ENCLAVE_LDLIBS)
	@echo "LINK =>  $@"

src/$(BENCH_INTERNAL_ESIGNED): src/$(BENCH_INTERNAL_ENCLAVE) $(SGX_KEY)
	@cd src && $(SGX_SIGN) sign -key $(SGX_KEY) \
			-enclave $(BENCH_INTERNAL_ENCLAVE) -out $(BENCH_INTERNAL_ESIGNED) \
			-config $(ENCLAVE_CONFIG_FILE)
	@echo "SIGN =>  $@"

BENCH_ECMULT_ENCLAVE := bench_ecmult.enclave.so
BENCH_ECMULT_ESIGNED := bench_ecmult.enclave.signed.so

BUILT_SOURCES += src/bench_ecmult_u.c src/bench_ecmult_u.h src/bench_ecmult_t.c src/bench_ecmult_t.h

src/bench_ecmult_u.c src/bench_ecmult_u.h: $(SGX_EDGER8R) src/bench_ecmult.edl
	@cd src && $(SGX_EDGER8R) --untrusted bench_ecmult.edl \
			--search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

src/bench_ecmult_u.o: src/bench_ecmult_u.c src/bench_ecmult_u.h
	@$(CC) $(SGX_APP_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

src/bench_ecmult_t.c src/bench_ecmult_t.h: $(SGX_EDGER8R) src/bench_ecmult.edl
	@cd src && $(SGX_EDGER8R) --trusted bench_ecmult.edl \
			--search-path $(top_srcdir)/src \
			--search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

src/bench_ecmult_t.o: src/bench_ecmult_t.c src/bench_ecmult_t.h
	@$(CC) $(SGX_ENCLAVE_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

src/bench_ecmult.o: src/bench_ecmult.c
	@$(CC) $(SGX_ENCLAVE_CFLAGS) -DHAVE_CONFIG_H \
			-DSECP256K1_BUILD -DVERIFY -I. -I./src -I$(top_srcdir)/src -I$(top_srcdir)/include \
			$(SECP_INCLUDES) $(SECP_TEST_INCLUDES) \
			-I/usr/include/x86_64-linux-gnu/ \
			-c $< -o $@
	@echo "CC   <=  $<"

BENCH_ECMULT_ENCLAVE_OBJS = src/sgx/t/util.o \
		src/bench_ecmult_t.o src/bench_ecmult.o

src/$(BENCH_ECMULT_ENCLAVE): $(BENCH_ECMULT_ENCLAVE_OBJS)
	$(CXX) $(SGX_ENCLAVE_CXXFLAGS) $(SGX_ENCLAVE_LDFLAGS) $^ -o  $@ $(SGX_ENCLAVE_LDLIBS)
	@echo "LINK =>  $@"

src/$(BENCH_ECMULT_ESIGNED): src/$(BENCH_ECMULT_ENCLAVE) $(SGX_KEY)
	@cd src && $(SGX_SIGN) sign -key $(SGX_KEY) \
			-enclave $(BENCH_ECMULT_ENCLAVE) -out $(BENCH_ECMULT_ESIGNED) \
			-config $(ENCLAVE_CONFIG_FILE)
	@echo "SIGN =>  $@"

bench_verify_SOURCES += src/bench_verify_u.c src/bench_verify_u.h src/sgx/u/util.c
bench_verify_CFLAGS = $(SGX_APP_CFLAGS)
bench_verify_LDFLAGS = $(SGX_APP_LDFLAGS)
bench_verify_LDADD += $(SGX_APP_LDLIBS) src/$(BENCH_VERIFY_ESIGNED)
bench_sign_SOURCES += src/bench_sign_u.c src/bench_sign_u.h src/sgx/u/util.c
bench_sign_CFLAGS = $(SGX_APP_CFLAGS)
bench_sign_LDFLAGS = $(SGX_APP_LDFLAGS)
bench_sign_LDADD += $(SGX_APP_LDLIBS) src/$(BENCH_SIGN_ESIGNED)
bench_internal_SOURCES += src/bench_internal_u.c src/bench_internal_u.h src/sgx/u/util.c
bench_internal_CFLAGS = $(SGX_APP_CFLAGS)
bench_internal_LDFLAGS = $(SGX_APP_LDFLAGS)
bench_internal_LDADD += $(SGX_APP_LDLIBS) src/$(BENCH_INTERNAL_ESIGNED)
bench_ecmult_SOURCES += src/bench_ecmult_u.c src/bench_ecmult_u.h src/sgx/u/util.c
bench_ecmult_CFLAGS = $(SGX_APP_CFLAGS)
bench_ecmult_LDFLAGS = $(SGX_APP_LDFLAGS)
bench_ecmult_LDADD += $(SGX_APP_LDLIBS) src/$(BENCH_ECMULT_ESIGNED)
endif
