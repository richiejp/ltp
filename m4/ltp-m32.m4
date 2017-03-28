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

AC_DEFUN([LTP_CHECK_CC_M32],[dnl

flag="-m32"
AC_MSG_CHECKING([if $CC supports $flag])

backup_cflags="$CFLAGS"
CFLAGS="$CFLAGS $flag"

AC_LINK_IFELSE(
	[AC_LANG_PROGRAM([])],
	[CC_M32="$flag"]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)

AC_SUBST(CC_M32)
CFLAGS="$backup_cflags"

])
