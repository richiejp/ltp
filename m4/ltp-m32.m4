dnl Copyright (c) 2017 Cyril Hrubis <chrubis@suse.cz>
dnl
dnl This program is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU General Public License as
dnl published by the Free Software Foundation; either version 2 of
dnl the License, or (at your option) any later version.
dnl
dnl This program is distributed in the hope that it would be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write the Free Software Foundation,
dnl Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
dnl

AC_DEFUN([LTP_CHECK_CFLAGS_M32],[dnl

flag="-m32"
AC_MSG_CHECKING([if $CC supports $flag])

backup_cflags="$CFLAGS"
CFLAGS="$CFLAGS $flag"

AC_LINK_IFELSE(
	[AC_LANG_PROGRAM([])],
	[CFLAGS_M32="$flag"]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)

AC_SUBST(CFLAGS_M32)

AC_MSG_CHECKING([for __sync_add_and_fetch with -m32])
AC_LINK_IFELSE([AC_LANG_SOURCE([
int main(void) {
	int i = 0;
	return __sync_add_and_fetch(&i, 1);
}])],[has_saac="yes"])

if test "x$has_saac" = xyes; then
	AC_DEFINE(HAVE_SYNC_ADD_AND_FETCH_M32,1,[Define to 1 if you have __sync_add_and_fetch with -m32])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

CFLAGS="$backup_cflags"
])
