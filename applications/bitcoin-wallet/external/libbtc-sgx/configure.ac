dnl require autoconf 2.68 (AS_ECHO/AS_ECHO_N)
AC_PREREQ([2.68])
AC_INIT([libbtc],[0.1],[https://github.com/jonasschnelli/libbtc/issues],[libbtc])
AC_CONFIG_HEADERS([src/libbtc-config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])
AC_CANONICAL_HOST
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AH_TOP([#ifndef LIBBTC_CONFIG_H])
AH_TOP([#define LIBBTC_CONFIG_H])
AH_BOTTOM([#endif /*LIBBTC_CONFIG_H*/])
AM_INIT_AUTOMAKE([no-define subdir-objects foreign])
AC_HEADER_STDBOOL
LT_INIT

PKG_PROG_PKG_CONFIG
AC_PATH_TOOL(AR, ar)
AC_PATH_TOOL(RANLIB, ranlib)
AC_PATH_TOOL(STRIP, strip)
#AM_PROG_CC_C_O
#AC_PROG_CC_C99

#CFLAGS="$CFLAGS -Wextra"
CFLAGS="-Wextra"

warn_CFLAGS="-std=c11 -Wno-unused-function -Wno-long-long -Wno-overlength-strings"
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS $warn_CFLAGS"
AC_MSG_CHECKING([if ${CC} supports ${warn_CFLAGS}])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[char foo;]])],
  [ AC_MSG_RESULT([yes]) ],
  [ AC_MSG_RESULT([no])
    CFLAGS="$saved_CFLAGS"
  ])

# Enable debug
AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug],
                  [use debug compiler flags and macros (default is no)])],
  [enable_debug=$enableval],
  [enable_debug=no])

AC_ARG_ENABLE([wallet],
  [AS_HELP_STRING([--disable-wallet],
  [disable wallet/database functions])],
  [with_wallet=$enableval],
  [with_wallet=yes])

AC_ARG_ENABLE([tools],
  [AS_HELP_STRING([--disable-tools],
  [disable bitcoin tool cli application])],
  [with_tools=$enableval],
  [with_tools=yes])

AC_ARG_ENABLE([net],
  [AS_HELP_STRING([--disable-net],
  [disable net functions])],
  [with_net=$enableval],
  [with_net=yes])

AC_ARG_WITH([sgx],
  [AS_HELP_STRING([--with-sgx],
  [use Intel SGX (default is no)])],
  [with_sgx=$withval],
  [with_sgx=no])

case $host in
  *mingw*)
     TARGET_OS=windows
     ;;
  *darwin*)
     TARGET_OS=darwin
     ;;
  *linux*)
     TARGET_OS=linux
     ;;
esac

if test "x$with_wallet" = xyes; then
  AC_DEFINE_UNQUOTED([WITH_WALLET],[1],[Define to 1 to enable wallet compilation])
fi

if test "x$with_tools" = xyes; then
AC_DEFINE_UNQUOTED([WITH_TOOLS],[1],[Define to 1 to enable wallet compilation])
fi

if test "x$with_net" = xyes; then
  AC_DEFINE_UNQUOTED([WITH_NET],[1],[Define to 1 to enable net compilation])
fi

if test x"$with_sgx" = x"yes"; then
  AC_DEFINE([WITH_SGX],[1],[Define to 1 to use Intel SGX])
fi

AC_ARG_VAR(SGX_MODE, [Hardware mode for SGX])
AC_ARG_VAR(SGX_DEBUG, [Debug mode for SGX])
AC_ARG_VAR(SGX_PRERELEASE, [Pre-release mode for SGX])

if test "x$enable_debug" = xyes; then
  CFLAGS="$CFLAGS -g3 -O0 -g -DDEBUG -UNDEBUG"
  CXXFLAGS="$CXXFLAGS -g3 -O0 -g -DDEBUG -UNDEBUG"
  AC_DEFINE_UNQUOTED([ENABLE_DEBUG],[1],[Define to 1 to enable debung output])
else
  CFLAGS="$CFLAGS -O2 -UDEBUG -DNDEBUG"
  CXXFLAGS="$CXXFLAGS -O2 -UDEBUG -DNDEBUG"
fi

AC_ARG_ENABLE(tests,
  AS_HELP_STRING([--enable-tests],[compile tests (default is yes)]),
  [use_tests=$enableval],
  [use_tests=yes])

AC_MSG_CHECKING([for __builtin_expect])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[void myfunc() {__builtin_expect(0,0);}]])],
  [ AC_MSG_RESULT([yes]);AC_DEFINE(HAVE_BUILTIN_EXPECT,1,[Define this symbol if __builtin_expect is available]) ],
  [ AC_MSG_RESULT([no])
  ])

m4_include(m4/macros/with.m4)
ARG_WITH_SET([random-device],      [/dev/urandom], [set the device to read random data from])
if test "x$random_device" = x"/dev/urandom"; then
  AC_DEFINE_UNQUOTED([FILE_RANDOM],[1],[Define to 1 to enable random retrieving over filehandle])
  AC_DEFINE([RANDOM_DEVICE],["/dev/urandom"],[Define to set random file handle])
fi
if test "x$random_device" = x"/dev/random"; then
  AC_DEFINE_UNQUOTED([FILE_RANDOM],[1],[Define to 1 to enable /dev/random as random device])
  AC_DEFINE([RANDOM_DEVICE],["/dev/random"],[Define to set random file handle])
fi

if test "$host" = "mingw"; then
  # -static is interpreted by libtool, where it has a different meaning.
  # In libtool-speak, it's -all-static.
  AX_CHECK_LINK_FLAG([[-static]],[LIBTOOL_APP_LDFLAGS="$LIBTOOL_APP_LDFLAGS -all-static"])
fi

if test x$with_net = "xyes"; then
  AC_CHECK_HEADER([event2/event.h],, AC_MSG_ERROR(libevent headers missing),)
  AC_CHECK_LIB([event],[main],EVENT_LIBS=-levent,AC_MSG_ERROR(libevent missing))
  if test "$host" = "mingw"; then
    AC_CHECK_LIB([event_pthreads],[main],EVENT_PTHREADS_LIBS=-levent_pthreads,AC_MSG_ERROR(libevent_pthreads missing))
  fi
fi

if test x"$with_sgx" = x"yes"; then
  SGX_COMMON_CPPFLAGS="-m64 -Iinclude -Isrc -Itest -I$SGX_SDK/include"
  SGX_COMMON_CFLAGS="-std=c11"
  SGX_COMMON_LDFLAGS="-L$SGX_SDK/lib64"
  # SGX_COMMON_LDFLAGS="-L$SGX_SDK/lib64 -Wl,-rpath,$SGX_SDK/lib64,--disable-new-dtags"
  if test "$SGX_DEBUG" = "1"; then
    SGX_COMMON_CPPFLAGS="$SGX_COMMON_CPPFLAGS -O0 -g -DDEBUG -UNDEBUG -UEDEBUG"
  else
    if test "$SGX_PRERELEASE" = "1"; then
      SGX_COMMON_CPPFLAGS="$SGX_COMMON_CPPFLAGS -O2 -UDEBUG -DNDEBUG -DEDEBUG"
    else
      SGX_COMMON_CPPFLAGS="$SGX_COMMON_CPPFLAGS -O2 -UDEBUG -DNDEBUG -UEDEBUG"
    fi
  fi
  SGX_APP_CPPFLAGS="$SGX_COMMON_CPPFLAGS"
  SGX_APP_CFLAGS="$SGX_COMMON_CFLAGS -fPIC -Wno-attributes"
  SGX_APP_LDFLAGS="$SGX_COMMON_LDFLAGS"
  #
  if test "$SGX_MODE" = "HW"; then
    SGX_APP_LDLIBS="-lsgx_urts -lpthread -lsgx_uae_service"
  else
    SGX_APP_LDLIBS="-lsgx_urts_sim -lpthread -lsgx_uae_service_sim"
  fi
  #
  SGX_ENC_CPPFLAGS="$SGX_COMMON_CPPFLAGS -include \"sgx.h\" \
      -I$SGX_SDK/include/tlibc \
      -I$SGX_SDK/include/libcxx"
  SGX_ENC_CFLAGS="$SGX_COMMON_CFLAGS -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong"
  SGX_ENC_LDFLAGS="$SGX_COMMON_LDFLAGS -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles"
  if test "$SGX_MODE" = "HW"; then
    SGX_ENC_LDLIBS="\
    -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
    -Wl,--start-group \
    -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice \
    -Wl,--end-group \
    -Wl,-Bstatic \
    -Wl,-Bsymbolic \
    -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry \
    -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0 \
    -Wl,--gc-sections \
    -Wl,--version-script=enclave.lds"
  else
    SGX_ENC_LDLIBS="\
    -Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive \
    -Wl,--start-group \
    -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice_sim \
    -Wl,--end-group \
    -Wl,-Bstatic \
    -Wl,-Bsymbolic \
    -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry \
    -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0 \
    -Wl,--gc-sections \
    -Wl,--version-script=enclave.lds"
  fi
  #
  #NOTE: SGX_MODE=SIM, DEBUG=1
  #TODO: add support for (pre-)release and HW
fi

AC_CONFIG_FILES([Makefile libbtc.pc])
AC_SUBST(LIBTOOL_APP_LDFLAGS)
AC_SUBST(BUILD_EXEEXT)
AC_SUBST(EVENT_LIBS)
AC_SUBST(EVENT_PTHREADS_LIBS)
AC_SUBST(SGX_APP_CPPFLAGS)
AC_SUBST(SGX_APP_CFLAGS)
#AC_SUBST(SGX_APP_CXXFLAGS)
AC_SUBST(SGX_APP_LDFLAGS)
AC_SUBST(SGX_APP_LDLIBS)
AC_SUBST(SGX_ENC_CPPFLAGS)
AC_SUBST(SGX_ENC_CFLAGS)
#AC_SUBST(SGX_ENC_CXXFLAGS)
AC_SUBST(SGX_ENC_LDFLAGS)
AC_SUBST(SGX_ENC_LDLIBS)
AM_CONDITIONAL([USE_TESTS], [test x"$use_tests" != x"no"])
AM_CONDITIONAL([WITH_TOOLS], [test "x$with_tools" = "xyes"])
AM_CONDITIONAL([WITH_WALLET], [test "x$with_wallet" = "xyes"])
AM_CONDITIONAL([WITH_NET], [test "x$with_net" = "xyes"])
AM_CONDITIONAL([WITH_SGX], [test x"$with_sgx" = x"yes"])

#original: ac_configure_args="${ac_configure_args} --enable-module-recovery"
if test x"$with_sgx" = x"yes"; then
  ac_configure_args="${ac_configure_args} --enable-module-recovery --with-bignum=no --disable-jni --enable-sgx SGX_MODE=${SGX_MODE} SGX_PRERELEASE=${SGX_PRERELEASE} SGX_DEBUG=${SGX_DEBUG}"
else
  ac_configure_args="${ac_configure_args} --enable-module-recovery --with-bignum=no --disable-jni --disable-sgx"
fi
AC_CONFIG_SUBDIRS([src/secp256k1])

dnl make sure nothing new is exported so that we don't break the cache
PKGCONFIG_PATH_TEMP="$PKG_CONFIG_PATH"
unset PKG_CONFIG_PATH
PKG_CONFIG_PATH="$PKGCONFIG_PATH_TEMP"

AC_OUTPUT

echo
echo "Options used to compile and link:"
echo "  with tests    = $use_tests"
echo "  with wallet   = $with_wallet"
echo "  with tools    = $with_tools"
echo "  with net      = $with_net"
echo "  with sgx      = $with_sgx"
echo
echo "  target os     = $TARGET_OS"
echo
echo "  CC            = $CC"
echo "  CFLAGS        = $CFLAGS"
echo "  CXX           = $CXX"
echo "  CXXFLAGS      = $CXXFLAGS"
echo "  LDFLAGS       = $LDFLAGS"
echo
if test x"$with_sgx" = x"yes"; then
echo "Enclave:"
echo "  CPPFLAGS      = $SGX_ENC_CPPFLAGS"
echo "  CFLAGS        = $SGX_ENC_CFLAGS"
echo "  CXXFLAGS      = $SGX_ENC_CXXFLAGS"
echo "  LDFLAGS       = $SGX_ENC_LDFLAGS"
echo "  LDLIBS        = $SGX_ENC_LDLIBS"
echo "Application:"
echo "  CPPFLAGS      = $SGX_APP_CPPFLAGS"
echo "  CFLAGS        = $SGX_APP_CFLAGS"
echo "  CXXFLAGS      = $SGX_APP_CXXFLAGS"
echo "  LDFLAGS       = $SGX_APP_LDFLAGS"
echo "  LDLIBS        = $SGX_APP_LDLIBS"
fi
echo
