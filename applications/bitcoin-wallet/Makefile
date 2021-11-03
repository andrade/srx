LIB_BTC ?= external/libbtc-sgx
LIB_BTC_RAW ?= external/libbtc-original
DEBUG ?= 1

SGX_MODE ?= SIM
SGX_DEBUG ?= 1
SGX_PRERELEASE ?= 0
CSP_MODE ?= 0

ifeq ($(DEBUG),1)
	DEBUG_FLAG := --enable-debug
	BENCHMARK_FLAG := --enable-benchmark
	TESTS_FLAG := --enable-tests
	EXHAUSTIVE_TESTS_FLAG := --enable-exhaustive-tests
else
	DEBUG_FLAG := --disable-debug
	BENCHMARK_FLAG := --disable-benchmark
	TESTS_FLAG := --disable-tests
	EXHAUSTIVE_TESTS_FLAG := --disable-exhaustive-tests
endif

all: tool

tool:
	cd external/libbtc-original && $(SHELL) autogen.sh && $(SHELL) configure --disable-shared --with-pic --with-bignum=no --enable-experimental --enable-module-ecdh --enable-module-recovery --disable-jni $(BENCHMARK_FLAG) $(TESTS_FLAG) $(EXHAUSTIVE_TESTS_FLAG) --prefix=/tmp/libbtc-original --disable-wallet --disable-tools --disable-net $(TESTS_FLAG) $(DEBUG_FLAG) && make
	cd external/libbtc-sgx && $(SHELL) autogen.sh && $(SHELL) configure --disable-shared --with-pic --with-bignum=no --enable-experimental --enable-module-ecdh --enable-module-recovery --disable-jni --enable-sgx $(BENCHMARK_FLAG) $(TESTS_FLAG) $(EXHAUSTIVE_TESTS_FLAG) --prefix=/tmp/libbtc-sgx --disable-wallet --disable-tools --disable-net $(TESTS_FLAG) $(DEBUG_FLAG) --with-sgx SGX_MODE=$(SGX_MODE) SGX_DEBUG=$(SGX_DEBUG) SGX_PRERELEASE=$(SGX_PRERELEASE) && make
	$(MAKE) -C modules/yapi SGX_MODE=$(SGX_MODE) SGX_DEBUG=$(SGX_DEBUG) SGX_PRERELEASE=$(SGX_PRERELEASE) CSP_MODE=$(CSP_MODE)
	$(MAKE) -C modules/yapitool SGX_MODE=$(SGX_MODE) SGX_DEBUG=$(SGX_DEBUG) SGX_PRERELEASE=$(SGX_PRERELEASE) CSP_MODE=$(CSP_MODE)

clean:
	$(MAKE) -C modules/yapitool clean
	$(MAKE) -C modules/yapi clean
	$(MAKE) -C external/libbtc-sgx clean
	$(MAKE) -C external/libbtc-original clean
