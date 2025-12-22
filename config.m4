dnl
dnl Signalforge Routing Extension
dnl config.m4 - Build configuration
dnl
dnl Copyright (c) 2024 Signalforge
dnl License: MIT
dnl

PHP_ARG_ENABLE([signalforge_routing],
  [whether to enable signalforge_routing support],
  [AS_HELP_STRING([--enable-signalforge-routing],
    [Enable signalforge_routing support])],
  [no])

if test "$PHP_SIGNALFORGE_ROUTING" != "no"; then

  dnl Check for PCRE2
  AC_MSG_CHECKING([for PCRE2])

  dnl Try pkg-config first
  if test -z "$PCRE2_DIR"; then
    AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
    if test "$PKG_CONFIG" != "no"; then
      if $PKG_CONFIG --exists libpcre2-8; then
        PCRE2_CFLAGS=`$PKG_CONFIG --cflags libpcre2-8`
        PCRE2_LIBS=`$PKG_CONFIG --libs libpcre2-8`
        AC_MSG_RESULT([found via pkg-config])
      fi
    fi
  fi

  dnl Check if pkg-config found it
  if test -z "$PCRE2_LIBS"; then
    dnl Try common locations
    for i in /usr/local /usr /opt/local /opt; do
      if test -f "$i/include/pcre2.h"; then
        PCRE2_DIR=$i
        break
      fi
    done

    if test -z "$PCRE2_DIR"; then
      AC_MSG_ERROR([Cannot find PCRE2 library. Please install libpcre2-dev])
    fi

    PCRE2_CFLAGS="-I$PCRE2_DIR/include"
    PCRE2_LIBS="-L$PCRE2_DIR/lib -lpcre2-8"
    AC_MSG_RESULT([found in $PCRE2_DIR])
  fi

  PHP_EVAL_INCLINE($PCRE2_CFLAGS)
  PHP_EVAL_LIBLINE($PCRE2_LIBS, SIGNALFORGE_ROUTING_SHARED_LIBADD)

  dnl Define PCRE2_CODE_UNIT_WIDTH
  AC_DEFINE([PCRE2_CODE_UNIT_WIDTH], [8], [PCRE2 code unit width])

  dnl Check for required headers
  AC_CHECK_HEADERS([pcre2.h], [], [
    AC_MSG_ERROR([pcre2.h not found. Please install libpcre2-dev])
  ], [
    #define PCRE2_CODE_UNIT_WIDTH 8
  ])

  dnl Source files
  PHP_NEW_EXTENSION(signalforge_routing,
    signalforge_routing.c routing_trie.c,
    $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1 $PCRE2_CFLAGS)

  PHP_SUBST(SIGNALFORGE_ROUTING_SHARED_LIBADD)

  dnl Add header files
  PHP_ADD_BUILD_DIR($ext_builddir)
  PHP_ADD_INCLUDE($ext_srcdir)

  dnl Install headers for potential use by other extensions
  PHP_INSTALL_HEADERS([ext/signalforge_routing], [
    signalforge_routing.h
    routing_trie.h
  ])

fi
