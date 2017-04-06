#
# lib32 Makefile.
#
# Copyright (C) 2017, Cyril Hrubis <chrubis@suse.cz>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

#
# We build the 32bit library only if -m32 is supported by the compiler
# it looks like some 32bit compilers does not support the flag while others
# do, hence the easiest solution is to build the library if we can.
#
top_srcdir		?= ..

include $(top_srcdir)/include/mk/env_pre.mk

ifneq ($(CFLAGS_M32),)

CFLAGS			+= -DLTPLIB -m32 -DM32

ifneq ($(ANDROID),1)
FILTER_OUT_DIRS		+= android_libpthread android_librt
else
FILTER_OUT_LIBSRCS	+= tlibio.c tst_path_has_mnt_flags.c
endif

LIB			:= libltp.a

include $(top_srcdir)/include/mk/lib.mk
include $(top_srcdir)/include/mk/generic_trunk_target.mk

else

all:

clean:

install:

endif
