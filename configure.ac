# Process this file with autoconf to produce a configure script.

# start out
AC_INIT([semblance], [1.0])
AC_CONFIG_SRCDIR([semblance.h])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_ARG_ENABLE(warn, AS_HELP_STRING([--disable-warn],[do not print warnings]))

# Check for availability of various components
AC_PROG_CC
AC_C_INLINE
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memmove memset strcasecmp strchr strdup strerror])

# set options
enable_warn=${enable_warn:-yes}
if test "x$enable_warn" = "xyes"
then
    AC_DEFINE([USE_WARN], 1, [Define to enable warnings])
fi

# build our environment
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
