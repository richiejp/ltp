dnl
dnl LTP_CHECK_CRYPTO
dnl ----------------------------
dnl
AC_DEFUN([LTP_CHECK_CRYPTO], [
	AC_CHECK_LIB([crypto], [SHA1_Init], [crypto_libs="-lcrypto"])
	AC_SUBST([CRYPTO_LIBS], [$crypto_libs])
	if test "x$have_libnuma" != "x"; then
		AC_DEFINE(HAVE_LIBCRYPTO,1,[define whether libcrypto is installed])
	fi
])
