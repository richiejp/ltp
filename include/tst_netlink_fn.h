/*
 * Copyright (c) 2018 Richard Palethorpe <rpalethorpe@suse.com>
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

#ifndef TST_NETLINK_FN_H
#define TST_NETLINK_FN_H

#include <linux/netlink.h>

#ifndef NETLINK_CRYPTO
#define NETLINK_CRYPTO 21
#endif

ssize_t tst_safe_netlink_send(const char *file, const int lineno,
			      int fd, const struct nlmsghdr *nh,
			      const void *payload);

ssize_t tst_safe_netlink_recv(const char *file, const int lineno,
			      int fd, char *nl_headers_buf,
			      size_t buf_len);

#endif	/* TST_NETLINK_FN_H */
