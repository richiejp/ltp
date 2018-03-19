/*
 * Copyright (c) 2018 Richard Palethorpe <rpalethorpe@suse.com>
 *                    Nicolai Stange <nstange@suse.de>
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

#define TST_NO_DEFAULT_MAIN
#include "tst_safe_net.h"
#include "tst_netlink.h"

ssize_t tst_safe_netlink_send(const char *file, const int lineno,
			      int fd, const struct nlmsghdr *nh,
			      const void *payload)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct iovec iov[2] = {
		{(struct nlmsghdr *)nh, sizeof(*nh)},
		{(void *)payload, nh->nlmsg_len - sizeof(*nh)}
	};
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = iov,
		.msg_iovlen = 2
	};

	return safe_sendmsg(file, lineno, nh->nlmsg_len, fd, &msg, 0);
}

ssize_t tst_safe_netlink_recv(const char *file, const int lineno,
			      int fd, char *nl_headers_buf, size_t buf_len)
{
	struct iovec iov = { nl_headers_buf, buf_len };
	struct sockaddr_nl sa;
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = &iov,
		.msg_iovlen = 1
	};

	return safe_recvmsg(file, lineno, 0, fd, &msg, 0);
}

