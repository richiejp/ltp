// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 SUSE
 *
 * Test transmitting data over a PTY/TTY line discipline and reading from the
 * virtual netdev created by the line discipline. Also hangup the PTY while
 * data is in flight to try to cause a race between the netdev being deleted
 * and the discipline receive function writing to the netdev.
 *
 * Test flow:
 * 1. Create PTY with ldisc X which creates netdev Y
 * 2. Open raw packet socket and bind to netdev Y
 * 3. Send data on ptmx and read packets from socket
 * 4. Hangup while transmission in progress
 *
 * Note that not all line disciplines call unthrottle when they are ready to
 * read more bytes. So it is possible to fill all the write buffers causing
 * write to block forever (because once write sleeps it needs unthrottle to
 * wake it). So we write with O_NONBLOCK.
 *
 * Also the max buffer size for PTYs is 8192, so even if the protocol MTU is
 * greater everything may still be processed in 8129 byte chunks. At least
 * until we are in the netdev code which can have a bigger buffer. Of course
 * the MTU still decides exactly where the packet delimiter goes, this just
 * concerns choosing the best packet size to cause a race.
 *
 * Note on line discipline encapsulation formats:
 * - For SLIP frames we just write the data followed by a delimiter char
 * - SLCAN we write some ASCII described in drivers/net/can/slcan.c which is
 *   converted to the actual frame by the kernel
 */

#define _GNU_SOURCE
#include "tst_test.h"
#include "tst_buffers.h"
#include "config.h"

#if defined(HAVE_LINUX_IF_PACKET_H) && defined(HAVE_LINUX_IF_ETHER_H)

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/tty.h>

#ifdef HAVE_LINUX_CAN_H
# include <linux/can.h>
#else
# define CAN_MTU 16
# define CAN_MAX_DLEN 8
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include "lapi/ioctl.h"

#include "tst_safe_stdio.h"

#define SLCAN_FRAME "t00185f5f5f5f5f5f5f5f\r"

struct ldisc_info {
	int n;
	char *name;
	int mtu;
};

static struct ldisc_info ldiscs[] = {
	{N_SLIP, "N_SLIP", 8192},
	{N_SLCAN, "N_SLCAN", CAN_MTU},
};

static volatile int ptmx, pts, sk, mtu, no_check;

static int set_ldisc(int tty, struct ldisc_info *ldisc)
{
	TEST(ioctl(tty, TIOCSETD, &ldisc->n));

	if (!TST_RET)
		return 0;

	if (TST_ERR == EINVAL) {
		tst_res(TCONF | TTERRNO,
			"You don't appear to have the %s TTY line discipline",
			ldisc->name);
	} else {
		tst_res(TFAIL | TTERRNO,
			"Failed to set the %s line discipline", ldisc->name);
	}

	return 1;
}

static int open_pty(struct ldisc_info *ldisc)
{
	char pts_path[PATH_MAX];

	ptmx = SAFE_OPEN("/dev/ptmx", O_RDWR);
	if (grantpt(ptmx))
		tst_brk(TBROK | TERRNO, "grantpt(ptmx)");
	if (unlockpt(ptmx))
		tst_brk(TBROK | TERRNO, "unlockpt(ptmx)");
	if (ptsname_r(ptmx, pts_path, sizeof(pts_path)))
		tst_brk(TBROK | TERRNO, "ptsname_r(ptmx, ...)");

	SAFE_FCNTL(ptmx, F_SETFL, O_NONBLOCK);

	tst_res(TINFO, "PTS path is %s", pts_path);
	pts = SAFE_OPEN(pts_path, O_RDWR);

	return set_ldisc(pts, ldisc);
}

static ssize_t try_write(int fd, char *data, ssize_t size, ssize_t *written)
{
	ssize_t ret = write(fd, data, size);

	if (ret < 0)
		return -(errno != EAGAIN);

	return !written || (*written += ret) >= size;
}

static void write_pty(struct ldisc_info *ldisc)
{
	char *data;
	ssize_t written, ret;
	size_t len = 0;

	switch (ldisc->n) {
	case N_SLIP:
		len = mtu; break;
	case N_SLCAN:
		len = sizeof(SLCAN_FRAME); break;
	}

	data = tst_alloc(len);

	switch (ldisc->n) {
	case N_SLIP:
		memset(data, '_', len - 1);
		data[len - 1] = 0300;
		break;
	case N_SLCAN:
		memcpy(data, SLCAN_FRAME, len);
		break;
	}


	written = 0;
	ret = TST_RETRY_FUNC(try_write(ptmx, data, len, &written), TST_RETVAL_NOTNULL);
	if (ret < 0)
		tst_brk(TBROK | TERRNO, "Failed 1st write to PTY");
	tst_res(TPASS, "Wrote PTY 1");

	written = 0;
	ret = TST_RETRY_FUNC(try_write(ptmx, data, len, &written), TST_RETVAL_NOTNULL);
	if (ret < 0)
		tst_brk(TBROK | TERRNO, "Failed 2nd write to PTY");

	if (tcflush(ptmx, TCIFLUSH))
		tst_brk(TBROK | TERRNO, "tcflush(ptmx, TCIFLUSH)");

	tst_res(TPASS, "Wrote PTY 2");

	while (try_write(ptmx, data, len, NULL) >= 0)
		;

	tst_res(TPASS, "Writing to PTY interrupted by hangup");

	tst_free_all();
}

static void open_netdev(struct ldisc_info *ldisc)
{
	struct ifreq ifreq = { 0 };
	struct sockaddr_ll lla = { 0 };

	SAFE_IOCTL(pts, SIOCGIFNAME, ifreq.ifr_name);
	tst_res(TINFO, "Netdev is %s", ifreq.ifr_name);

	sk = SAFE_SOCKET(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	ifreq.ifr_mtu = ldisc->mtu;
	if (ioctl(sk, SIOCSIFMTU, &ifreq))
		tst_res(TWARN | TERRNO, "Failed to set netdev MTU to maximum");
	SAFE_IOCTL(sk, SIOCGIFMTU, &ifreq);
	mtu = ifreq.ifr_mtu;
	tst_res(TINFO, "Netdev MTU is %d (we set %d)", mtu, ldisc->mtu);

	SAFE_IOCTL(sk, SIOCGIFFLAGS, &ifreq);
	ifreq.ifr_flags |= IFF_UP | IFF_RUNNING;
	SAFE_IOCTL(sk, SIOCSIFFLAGS, &ifreq);
	SAFE_IOCTL(sk, SIOCGIFFLAGS, &ifreq);

	if (!(ifreq.ifr_flags & IFF_UP))
		tst_brk(TBROK, "Netdev did not come up");

	SAFE_IOCTL(sk, SIOCGIFINDEX, &ifreq);

	lla.sll_family = PF_PACKET;
	lla.sll_protocol = htons(ETH_P_ALL);
	lla.sll_ifindex = ifreq.ifr_ifindex;
	SAFE_BIND(sk, (struct sockaddr *)&lla, sizeof(struct sockaddr_ll));

	tst_res(TINFO, "Bound netdev %d to socket %d", ifreq.ifr_ifindex, sk);
}

static void check_data(const char *data, ssize_t len)
{
	ssize_t i = 0, j;

	if (no_check)
		return;

	do {
		if (i >= len)
			return;
	} while (data[i++] == '_');

	j = i--;

	while (j < len && j - i < 65 && data[j++] != '_')
		;
	j--;

	tst_res_hexd(TFAIL, data + i, j - i,
		     "Corrupt data (max 64 of %ld bytes shown): data[%ld..%ld] = ",
		     len, i, j);
	tst_res(TINFO, "Will continue test without data checking");
	no_check = 1;
}

static void read_netdev(struct ldisc_info *ldisc)
{
	int rlen, plen = 0;
	char *data;

	switch (ldisc->n) {
	case N_SLIP:
		plen = mtu - 1;
		break;

#ifdef HAVE_LINUX_CAN_H
	case N_SLCAN:
		plen = CAN_MTU;
		break;
#endif
	}
	data = tst_alloc(plen);

	tst_res(TINFO, "Reading from socket %d", sk);

	SAFE_READ(1, sk, data, plen);
	check_data(data, plen);
	tst_res(TPASS, "Read netdev 1");

	SAFE_READ(1, sk, data, plen);
	check_data(data, plen);
	tst_res(TPASS, "Read netdev 2");

	TST_CHECKPOINT_WAKE(0);
	while((rlen = read(sk, data, plen)) > 0)
		check_data(data, rlen);

	tst_res(TPASS, "Reading data from netdev interrupted by hangup");

	tst_free_all();
}

static void do_test(unsigned int n)
{
	struct ldisc_info *ldisc = &ldiscs[n];

	if (open_pty(ldisc))
		return;

	open_netdev(ldisc);

	if (!SAFE_FORK()) {
		read_netdev(ldisc);
		return;
	}

	if (!SAFE_FORK()) {
		write_pty(ldisc);
		return;
	}

	if (!SAFE_FORK()) {
		TST_CHECKPOINT_WAIT(0);
		SAFE_IOCTL(pts, TIOCVHANGUP);
		tst_res(TINFO, "Sent hangup ioctl to PTS");
		SAFE_IOCTL(ptmx, TIOCVHANGUP);
		tst_res(TINFO, "Sent hangup ioctl to PTM");
		return;
	}

	tst_reap_children();
}

static void cleanup(void)
{
	ioctl(pts, TIOCVHANGUP);
	ioctl(ptmx, TIOCVHANGUP);

	tst_reap_children();
}

static struct tst_test test = {
	.test = do_test,
	.cleanup = cleanup,
	.tcnt = 2,
	.forks_child = 1,
	.needs_checkpoints = 1,
	.needs_root = 1,
	.min_kver = "4.10"
};

#else

TST_TEST_TCONF("Need <linux/if_packet.h> and <linux/if_ether.h>");

#endif
