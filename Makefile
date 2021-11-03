PLATFORM_ID ?= 0
AUTOFILL ?= 0
DEBUG ?= 0
SGX_MODE ?= HW
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 1
CSP_MODE ?= 1

# How to use this Makefile.
#
# Compile for development, in HW mode:
# $ make build PLATFORM_ID=0 DEBUG=1 SGX_MODE=HW SGX_DEBUG=1 SGX_PRERELEASE=0 CSP_MODE=0
#
# Compile for experimental evaluation:
# $ make build PLATFORM_ID=0 DEBUG=0 SGX_MODE=HW SGX_DEBUG=0 SGX_PRERELEASE=1 CSP_MODE=1
#
# Compile for experimental evaluation (with autofill and no GUI):
# $ make build PLATFORM_ID=0 AUTOFILL=1 DEBUG=0 SGX_MODE=HW SGX_DEBUG=0 SGX_PRERELEASE=1 CSP_MODE=1
#
# Use PLATFORM_ID=0 to simulate multiple platforms.

# Error checks:

ifndef SRX_HOME
$(error SRX_HOME is not set)
endif

ifndef SRX_API
$(error SRX_API is not set)
endif

ifndef SGX_SDK
$(error SGX_SDK is not set)
endif

ifndef SGX_SSL
$(error SGX_SSL is not set)
endif

ifndef SRX_OPENSSL
$(error SRX_OPENSSL is not set)
endif

# Setup variables:

ifeq ($(AUTOFILL),1)
	SRX_DEBUG_AUTOFILL=1
	SRX_DEBUG_PRINT_VERIFICATION_CODE=0
else
	SRX_DEBUG_AUTOFILL=0
	SRX_DEBUG_PRINT_VERIFICATION_CODE=1
endif

# Building:

info:
	$(info -------------------------------- top-level makefile --------)
	$(info [path][SRX_HOME  ] $(SRX_HOME))
	$(info [path][SRX_API   ] $(SRX_API))
	$(info [path][SGX_SDK   ] $(SGX_SDK))
	$(info [path][SGX_SSL   ] $(SGX_SSL))
	$(info [flag][PLATFORM_ID] $(PLATFORM_ID))
	$(info [flag][AUTOFILL  ] $(AUTOFILL))
	$(info [flag][DEBUG     ] $(DEBUG))
	$(info [flag][SGX_MODE  ] $(SGX_MODE))
	$(info [flag][SGX_DEBUG ] $(SGX_DEBUG))
	$(info [flag][SGX_PRERELEASE] $(SGX_PRERELEASE))
	$(info [flag][CSP_MODE  ] $(CSP_MODE))
	$(info ------------------------------------------------------------)

build: info
	$(MAKE) -C support-libs/usgx/
	$(MAKE) -C support-libs/foossl/
	$(MAKE) -C srx-libs/android-st/common/
	$(MAKE) -C srx-libs/android-st/protocol/ generate
	$(MAKE) -C srx-libs/android-st/protocol/
	$(MAKE) -C srx-libs/android-st/client/ RLOG=RLOG_INFO SRX_DEBUG=1 SRX_DEBUG_PRINT_VERIFICATION_CODE=$(SRX_DEBUG_PRINT_VERIFICATION_CODE) SRX_DEBUG_AUTOFILL=$(SRX_DEBUG_AUTOFILL) PLATFORM_ID=$(PLATFORM_ID) SGX_DEBUG=$(SGX_DEBUG) SGX_PRERELEASE=$(SGX_PRERELEASE)
	$(MAKE) -C applications/server/
	$(MAKE) -C applications/sample-pst/ SGX_MODE=$(SGX_MODE) SGX_DEBUG=$(SGX_DEBUG) SGX_PRERELEASE=$(SGX_PRERELEASE)
	$(MAKE) -C applications/bitcoin-wallet/ DEBUG=$(DEBUG) SGX_MODE=$(SGX_MODE) SGX_DEBUG=$(SGX_DEBUG) SGX_PRERELEASE=$(SGX_PRERELEASE) CSP_MODE=$(CSP_MODE)
	$(MAKE) -C applications/password-manager/ SGX_MODE=$(SGX_MODE) SGX_DEBUG=$(SGX_DEBUG) SGX_PRERELEASE=$(SGX_PRERELEASE) CSP_MODE=$(CSP_MODE)

clean: info
	$(MAKE) -C support-libs/usgx/ clean
	$(MAKE) -C support-libs/foossl/ clean
	$(MAKE) -C srx-libs/android-st/common/ clean
	$(MAKE) -C srx-libs/android-st/protocol/ clean
	$(MAKE) -C srx-libs/android-st/client/ clean
	$(MAKE) -C applications/server/ clean
	$(MAKE) -C applications/sample-pst/ clean
	$(MAKE) -C applications/password-manager/ clean
	$(MAKE) -C applications/bitcoin-wallet/ clean
