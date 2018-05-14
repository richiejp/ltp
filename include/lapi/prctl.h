/*
 * Copyright (c) 2018 Richard Palethorpe <rpalethorp@suse.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef PRCTL_H__
#define PRCTL_H__

#include "../config.h"

#ifdef HAVE_SYS_PRCTL_H
# include <sys/prctl.h>
#endif

#ifndef CAP_NET_ADMIN
# define CAP_NET_ADMIN 12
#endif

#ifndef CAP_NET_RAW
# define CAP_NET_RAW 13
#endif

#ifndef CAP_SYS_MODULE
# define CAP_SYS_MODULE 16
#endif

#ifndef CAP_SYS_RAWIO
# define CAP_SYS_RAWIO 17
#endif

#ifndef CAP_SYS_ADMIN
# define CAP_SYS_ADMIN 21
#endif

#endif /* PRCTL_H__ */
