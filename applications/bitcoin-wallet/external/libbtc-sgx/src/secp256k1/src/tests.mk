noinst_PROGRAMS += tests
tests_SOURCES = src/tests_bootstrap.c
tests_CPPFLAGS = -DSECP256K1_BUILD -I$(top_srcdir)/src -I$(top_srcdir)/include $(SECP_INCLUDES) $(SECP_TEST_INCLUDES)
if !ENABLE_COVERAGE
tests_CPPFLAGS += -DVERIFY
endif
tests_LDADD = $(SECP_LIBS) $(SECP_TEST_LIBS) $(COMMON_LIB)
tests_LDFLAGS = #-static
if !ENABLE_SGX
tests_SOURCES += src/tests.c
else
TESTS_ENCLAVE := tests.enclave.so
TESTS_ESIGNED := tests.enclave.signed.so

BUILT_SOURCES += src/tests_u.c src/tests_u.h src/tests_t.c src/tests_t.h

src/tests_u.c src/tests_u.h: $(SGX_EDGER8R) src/tests.edl
	@cd src && $(SGX_EDGER8R) --untrusted tests.edl \
			--search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

src/tests_u.o: src/tests_u.c src/tests_u.h
	@$(CC) $(SGX_APP_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

src/tests_t.c src/tests_t.h: $(SGX_EDGER8R) src/tests.edl
	@cd src && $(SGX_EDGER8R) --trusted tests.edl \
			--search-path $(top_srcdir)/src \
			--search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

src/tests_t.o: src/tests_t.c src/tests_t.h
	@$(CC) $(SGX_ENCLAVE_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

# $(DEFS) contains -DHAVE_CONFIG_H -- best approach is to libtoolize all of it
# perhaps use a hack and place this stuff on a todo.d list  or roadmap.
src/tests.o: src/tests.c $(HEADERS)
	@$(CC) $(SGX_ENCLAVE_CFLAGS) -DHAVE_CONFIG_H \
			-DSECP256K1_BUILD -DVERIFY -I. -I./src -I$(top_srcdir)/src -I$(top_srcdir)/include \
			$(SECP_INCLUDES) $(SECP_TEST_INCLUDES) \
			-c $< -o $@
#-I/usr/include/x86_64-linux-gnu/ # remove da regra em cima (ñ faz sentido porque estamos a compilar algo dentro do enclave) TORM
#	@$(CXX) $(SGX_ENCLAVE_CXXFLAGS) $(DEFS) -DSECP256K1_BUILD -I$(top_srcdir) -I$(top_srcdir)/src -I$(top_srcdir)/include $(SECP_INCLUDES) $(SECP_TEST_INCLUDES) -c $< -o $@
	@echo "CC   <=  $<"

TESTS_ENCLAVE_OBJS = src/tests_t.o src/sgx/t/util.o src/tests.o
src/$(TESTS_ENCLAVE): $(TESTS_ENCLAVE_OBJS) $(LIBSECP256K1_A)
	$(CXX) $(SGX_ENCLAVE_CXXFLAGS) $(SGX_ENCLAVE_LDFLAGS) $^ -o  $@ $(SGX_ENCLAVE_LDLIBS)
#	$(LIBTOOL) --mode=link $(CXX) $(SGX_ENCLAVE_LDFLAGS) $^ -o  $@ $(SGX_ENCLAVE_LDLIBS)
	@echo "LINK =>  $@"
#src/$(ENCLAVE_NAME): src/enclave_t.o src/enclave.o src/tests.o $(lib_LTLIBRARIES)
#	$(CXX) $^ -I$(top_srcdir)/include -I$(top_srcdir)/contrib -I$(top_srcdir)/src $(SECP_INCLUDES) -o  $@ $(SGX_ENCLAVE_LDFLAGS) $(SGX_ENCLAVE_LDLIBS) \
#		$(JNI_LIB) $(SECP_LIBS) $(COMMON_LIB)
#	@echo "LINK =>  $@"

src/$(TESTS_ESIGNED): src/$(TESTS_ENCLAVE) $(SGX_KEY)
	@cd src && $(SGX_SIGN) sign -key $(SGX_KEY) \
			-enclave $(TESTS_ENCLAVE) -out $(TESTS_ESIGNED) \
			-config $(ENCLAVE_CONFIG_FILE)

tests_SOURCES += src/tests_u.c src/tests_u.h src/sgx/u/util.c
tests_CFLAGS = $(SGX_APP_CFLAGS)
tests_CXXFLAGS = $(SGX_APP_CXXFLAGS)
tests_LDFLAGS += $(SGX_APP_LDFLAGS)
tests_LDADD += $(SGX_APP_LDLIBS) src/$(TESTS_ESIGNED)
#src/$(SIGNED_ENCLAVE_NAME)
endif
TESTS += tests
