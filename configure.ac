# Process this file with autoconf to produce a configure script.

# start out
AC_INIT([semblance], [1.0])
AC_CONFIG_SRCDIR([semblance.h])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

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

# build our environment
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
