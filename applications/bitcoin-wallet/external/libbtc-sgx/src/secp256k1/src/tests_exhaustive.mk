noinst_PROGRAMS += exhaustive_tests
exhaustive_tests_SOURCES = src/tests_exhaustive_bootstrap.c
exhaustive_tests_CPPFLAGS = -DSECP256K1_BUILD -I$(top_srcdir)/src $(SECP_INCLUDES)
if !ENABLE_COVERAGE
exhaustive_tests_CPPFLAGS += -DVERIFY
endif
exhaustive_tests_LDADD = $(SECP_LIBS)
exhaustive_tests_LDFLAGS = #-static#XXX
if !ENABLE_SGX
exhaustive_tests_SOURCES += src/tests_exhaustive.c
else
EXHAUSTIVE_TESTS_ENCLAVE := exhaustive_tests.enclave.so
EXHAUSTIVE_TESTS_ESIGNED := exhaustive_tests.enclave.signed.so

BUILT_SOURCES += src/tests_exhaustive_u.c src/tests_exhaustive_u.h src/tests_exhaustive_t.c src/tests_exhaustive_t.h

src/tests_exhaustive_u.c src/tests_exhaustive_u.h: $(SGX_EDGER8R) src/tests_exhaustive.edl
	@cd src && $(SGX_EDGER8R) --untrusted tests_exhaustive.edl \
			--search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

src/tests_exhaustive_u.o: src/tests_exhaustive_u.c src/tests_exhaustive_u.h
	@$(CC) $(SGX_APP_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

src/tests_exhaustive_t.c src/tests_exhaustive_t.h: $(SGX_EDGER8R) src/tests_exhaustive.edl
	@cd src && $(SGX_EDGER8R) --trusted tests_exhaustive.edl \
			--search-path $(top_srcdir)/src \
			--search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

src/tests_exhaustive_t.o: src/tests_exhaustive_t.c src/tests_exhaustive_t.h
	@$(CC) $(SGX_ENCLAVE_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

src/tests_exhaustive.o: src/tests_exhaustive.c $(HEADERS)
	@$(CC) $(SGX_ENCLAVE_CFLAGS) -DHAVE_CONFIG_H \
			-DSECP256K1_BUILD -DVERIFY -I. -I./src -I$(top_srcdir)/src -I$(top_srcdir)/include \
			$(SECP_INCLUDES) $(SECP_TEST_INCLUDES) \
			-c $< -o $@
	@echo "CC   <=  $<"
#			-I/usr/include/x86_64-linux-gnu/

EXHAUSTIVE_TESTS_ENCLAVE_OBJS = src/sgx/t/util.o \
		src/tests_exhaustive_t.o src/tests_exhaustive.o

src/$(EXHAUSTIVE_TESTS_ENCLAVE): $(EXHAUSTIVE_TESTS_ENCLAVE_OBJS) $(LIBSECP256K1_A)
	$(CXX) $(SGX_ENCLAVE_CXXFLAGS) $(SGX_ENCLAVE_LDFLAGS) $^ -o  $@ $(SGX_ENCLAVE_LDLIBS)
	@echo "LINK =>  $@"

src/$(EXHAUSTIVE_TESTS_ESIGNED): src/$(EXHAUSTIVE_TESTS_ENCLAVE) $(SGX_KEY)
	@cd src && $(SGX_SIGN) sign -key $(SGX_KEY) \
			-enclave $(EXHAUSTIVE_TESTS_ENCLAVE) -out $(EXHAUSTIVE_TESTS_ESIGNED) \
			-config $(ENCLAVE_CONFIG_FILE)

exhaustive_tests_SOURCES += src/sgx/u/util.c src/tests_exhaustive_u.c src/tests_exhaustive_u.h
exhaustive_tests_CFLAGS = $(SGX_APP_CFLAGS)
exhaustive_tests_CXXFLAGS = $(SGX_APP_CXXFLAGS)
exhaustive_tests_LDFLAGS += $(SGX_APP_LDFLAGS)
exhaustive_tests_LDADD += $(SGX_APP_LDLIBS) src/$(EXHAUSTIVE_TESTS_ESIGNED)
endif
TESTS += exhaustive_tests
