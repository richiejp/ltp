#include <net/if.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/in6.h>
#include <linux/neighbour.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

#define DEV_IPV4 "172.20.20.%d"
#define DEV_IPV6 "fe80::%02x"
#define DEV_MAC 0x00aaaaaaaaaa

static struct {
	char *pos;
	unsigned int depth;
	struct nlattr* stack[8];
	char buf[BUFSIZ];
} msg;

static struct {
	const char *type;
	const char *name;
} net_devtypes[] = {
	{"ip6gretap", "ip6gretap0"},
	{"bridge", "bridge0"},
	{"vcan", "vcan0"},
	{"bond", "bond0"},
	{"team", "team0"},
	{"dummy", "dummy0"},
	{"nlmon", "nlmon0"},
	{"caif", "caif0"},
	{"batadv", "batadv0"},
	{"vxcan", "vxcan1"},
	{"netdevsim", "netdevsim0"},
	{"veth", 0},
};

const char* devmasters[] = {"bridge", "bond", "team"};

static struct {
	const char* name;
	int macsize;
	char noipv6;
} net_devices[] = {
	{"lo", ETH_ALEN, 0},
	{"sit0", 0, 0},
	{"bridge0", ETH_ALEN, 0},
	{"vcan0", 0, 1},
	{"tunl0", 0, 0},
	{"gre0", 0, 0},
	{"gretap0", ETH_ALEN, 0},
	{"ip_vti0", 0, 0},
	{"ip6_vti0", 0, 0},
	{"ip6tnl0", 0, 0},
	{"ip6gre0", 0, 0},
	{"ip6gretap0", ETH_ALEN, 0},
	{"erspan0", ETH_ALEN, 0},
	{"bond0", ETH_ALEN, 0},
	{"veth0", ETH_ALEN, 0},
	{"veth1", ETH_ALEN, 0},
	{"team0", ETH_ALEN, 0},
	{"veth0_to_bridge", ETH_ALEN, 0},
	{"veth1_to_bridge", ETH_ALEN, 0},
	{"veth0_to_bond", ETH_ALEN, 0},
	{"veth1_to_bond", ETH_ALEN, 0},
	{"veth0_to_team", ETH_ALEN, 0},
	{"veth1_to_team", ETH_ALEN, 0},
	{"veth0_to_hsr", ETH_ALEN, 0},
	{"veth1_to_hsr", ETH_ALEN, 0},
	{"hsr0", 0, 0},
	{"dummy0", ETH_ALEN, 0},
	{"nlmon0", 0, 0},
	{"vxcan1", 0, 1},
	{"batadv0", ETH_ALEN, 0},
	{"netdevsim0", ETH_ALEN, 0},
};

static void nlmsg_write_head(uint16_t type, uint16_t flags,
			     const void *data, uint32_t size)
{
	struct nlmsghdr* hdr = (struct nlmsghdr*)msg.buf;

	memset(&msg, 0, sizeof(msg));

	hdr->nlmsg_type = type;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;

	memcpy(hdr + 1, data, size);

	msg.pos = (char *)(hdr + 1) + NLMSG_ALIGN(size);
}

static void nlmsg_write_attr(uint16_t type, const void* data, int size)
{
	struct nlattr* attr = (struct nlattr*)msg.pos;

	attr->nla_len = sizeof(*attr) + size;
	attr->nla_type = type;

	memcpy(attr + 1, data, size);

	msg.pos += NLMSG_ALIGN(attr->nla_len);
}

static void nlmsg_push_attr(uint16_t type)
{
	struct nlattr* attr = (struct nlattr*)msg.pos;

	attr->nla_type = type;

	msg.pos += sizeof(*attr);
	msg.stack[msg.depth++] = attr;
}

static void nlmsg_pop_attr(void)
{
	struct nlattr* attr = msg.stack[--msg.depth];

	attr->nla_len = msg.pos - (char*)attr;
}

static int nlmsg_send(int sock)
{
	struct nlmsghdr* hdr = (struct nlmsghdr*)msg.buf;
	struct sockaddr_nl addr;
	unsigned n;

	if (msg.pos > msg.buf + sizeof(msg.buf) || msg.depth)
		tst_brk(TBROK, "nlmsg attribute overflow/bad nesting");

	hdr->nlmsg_len = msg.pos - msg.buf;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	SAFE_SENDTO(1, sock, msg.buf, hdr->nlmsg_len, 0, (struct sockaddr*)&addr, sizeof(addr));

	n = recv(sock, msg.buf, sizeof(msg.buf), 0);
	if (n < sizeof(struct nlmsghdr) + sizeof(struct nlmsgerr))
		tst_brk(TBROK, "short netlink read: %d", n);
	if (hdr->nlmsg_type != NLMSG_ERROR)
		tst_brk(TBROK, "short netlink ack: %d", hdr->nlmsg_type);

	return -((struct nlmsgerr*)(hdr + 1))->error;
}

static void nlmsg_add_device_head(const char* type, const char* name)
{
	struct ifinfomsg hdr;

	memset(&hdr, 0, sizeof(hdr));
	nlmsg_write_head(RTM_NEWLINK, NLM_F_EXCL | NLM_F_CREATE, &hdr, sizeof(hdr));
	if (name)
		nlmsg_write_attr(IFLA_IFNAME, name, strlen(name));

	nlmsg_push_attr(IFLA_LINKINFO);
	nlmsg_write_attr(IFLA_INFO_KIND, type, strlen(type));
}

static void nl_add_device(int sock, const char* type, const char* name)
{
	nlmsg_add_device_head(type, name);

	nlmsg_pop_attr(); 	/* LINKINFO */

	int err = nlmsg_send(sock);
	if (loud) {
		tst_res(TINFO, "adding device %s type %s: %s",
			name, type, strerror(err));
	}

	(void)err;
}

static void nl_add_veth(int sock, const char* name, const char* peer)
{
	nlmsg_add_device_head("veth", name);

	nlmsg_push_attr(IFLA_INFO_DATA);
	nlmsg_push_attr(VETH_INFO_PEER);
	msg.pos += sizeof(struct ifinfomsg);
	nlmsg_write_attr(IFLA_IFNAME, peer, strlen(peer));
	nlmsg_pop_attr();
	nlmsg_pop_attr();

	nlmsg_pop_attr(); 	/* LINKINFO */

	int err = nlmsg_send(sock);
	if (loud) {
		tst_res(TINFO, "adding device %s type veth peer %s: %s",
			name, peer, strerror(err));
	}

	(void)err;
}

static void nl_add_hsr(int sock, const char* name,
		       const char* slave1, const char* slave2)
{
	int ifindex1, ifindex2, err;

	nlmsg_add_device_head("hsr", name);

	nlmsg_push_attr(IFLA_INFO_DATA);
	ifindex1 = if_nametoindex(slave1);
	nlmsg_write_attr(IFLA_HSR_SLAVE1, &ifindex1, sizeof(ifindex1));
	ifindex2 = if_nametoindex(slave2);
	nlmsg_write_attr(IFLA_HSR_SLAVE2, &ifindex2, sizeof(ifindex2));
	nlmsg_pop_attr();

	nlmsg_pop_attr(); 	/* LINKINFO */

	err = nlmsg_send(sock);
	if (loud) {
		tst_res(TINFO, "adding device %s type hsr slave1 %s slave2 %s: %s",
			name, slave1, slave2, strerror(err));
	}

	(void)err;
}

static void nl_device_change(int sock, const char* name, char up,
				  const char* master, const void* mac, int macsize)
{
	struct ifinfomsg hdr;
	int ifindex, err;

	memset(&hdr, 0, sizeof(hdr));
	hdr.ifi_flags = hdr.ifi_change = up ? IFF_UP : 0;
	nlmsg_write_head(RTM_NEWLINK, 0, &hdr, sizeof(hdr));

	nlmsg_write_attr(IFLA_IFNAME, name, strlen(name));

	if (master) {
		ifindex = if_nametoindex(master);
		nlmsg_write_attr(IFLA_MASTER, &ifindex, sizeof(ifindex));
	}

	if (macsize)
		nlmsg_write_attr(IFLA_ADDRESS, mac, macsize);

	err = nlmsg_send(sock);
	if (loud) {
		tst_res(TINFO, "device %s up master %s: %s",
			name, master, strerror(err));
	}

	(void)err;
}

static int nl_add_addr(int sock, const char* dev,
			    const void* addr, int addrsize)
{
	struct ifaddrmsg hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.ifa_family = addrsize == 4 ? AF_INET : AF_INET6;
	hdr.ifa_prefixlen = addrsize == 4 ? 24 : 120;
	hdr.ifa_scope = RT_SCOPE_UNIVERSE;
	hdr.ifa_index = if_nametoindex(dev);

	nlmsg_write_head(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, &hdr, sizeof(hdr));

	nlmsg_write_attr(IFA_LOCAL, addr, addrsize);
	nlmsg_write_attr(IFA_ADDRESS, addr, addrsize);

	return nlmsg_send(sock);
}

static void nl_add_addr4(int sock, const char* dev, const char* addr)
{
	struct in_addr in_addr;
	int err;

	inet_pton(AF_INET, addr, &in_addr);
	err = nl_add_addr(sock, dev, &in_addr, sizeof(in_addr));
	if (loud)
		tst_res(TINFO, "add addr %s dev %s: %s", addr, dev, strerror(err));

	(void)err;
}

static void nl_add_addr6(int sock, const char* dev, const char* addr)
{
	struct in6_addr in6_addr;
	int err;

	inet_pton(AF_INET6, addr, &in6_addr);
	err = nl_add_addr(sock, dev, &in6_addr, sizeof(in6_addr));
	if (loud)
		tst_res(TINFO, "add addr %s dev %s: %s", addr, dev, strerror(err));

	(void)err;
}

static void nl_add_neigh(int sock, const char* name,
			 const void* addr, int addrsize,
			 const void* mac, int macsize)
{
	struct ndmsg hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.ndm_family = addrsize == 4 ? AF_INET : AF_INET6;
	hdr.ndm_ifindex = if_nametoindex(name);
	hdr.ndm_state = NUD_PERMANENT;

	nlmsg_write_head(RTM_NEWNEIGH, NLM_F_EXCL | NLM_F_CREATE,
			 &hdr, sizeof(hdr));
	nlmsg_write_attr(NDA_DST, addr, addrsize);
	nlmsg_write_attr(NDA_LLADDR, mac, macsize);

	err = nlmsg_send(sock);
	if (loud) {
		tst_res(TINFO, "add neigh %s addr %d lladdr %d: %s",
			name, addrsize, macsize, strerror(err));
	}

	(void)err;
}

static void create_network_devices(void)
{
	int sock;
	unsigned i;
	char master[32], slave0[32], veth0[32], slave1[32], veth1[32], addr[32];
	uint64_t macaddr;

	if (unshare(CLONE_NEWNET)) {
		if (loud) {
			tst_res(TINFO | TERRNO,
				"Failed to create network namespace; won't try to create network devices");
		}
		return;
	}

	sock = SAFE_SOCKET(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	for (i = 0; i < ARRAY_SIZE(net_devtypes); i++)
		nl_add_device(sock, net_devtypes[i].type, net_devtypes[i].name);

	for (i = 0; i < sizeof(devmasters) / (sizeof(devmasters[0])); i++) {
		sprintf(slave0, "%s_slave_0", devmasters[i]);
		sprintf(veth0, "veth0_to_%s", devmasters[i]);
		nl_add_veth(sock, slave0, veth0);

		sprintf(slave1, "%s_slave_1", devmasters[i]);
		sprintf(veth1, "veth1_to_%s", devmasters[i]);
		nl_add_veth(sock, slave1, veth1);

		sprintf(master, "%s0", devmasters[i]);
		nl_device_change(sock, slave0, 0, master, 0, 0);
		nl_device_change(sock, slave1, 0, master, 0, 0);
	}

	nl_device_change(sock, "bridge_slave_0", 1, 0, 0, 0);
	nl_device_change(sock, "bridge_slave_1", 1, 0, 0, 0);

	nl_add_veth(sock, "hsr_slave_0", "veth0_to_hsr");
	nl_add_veth(sock, "hsr_slave_1", "veth1_to_hsr");
	nl_add_hsr(sock, "hsr0", "hsr_slave_0", "hsr_slave_1");
	nl_device_change(sock, "hsr_slave_0", 1, 0, 0, 0);
	nl_device_change(sock, "hsr_slave_1", 1, 0, 0, 0);

	for (i = 0; i < sizeof(net_devices) / (sizeof(net_devices[0])); i++) {
		sprintf(addr, DEV_IPV4, i + 10);
		nl_add_addr4(sock, net_devices[i].name, addr);

		if (!net_devices[i].noipv6) {
			sprintf(addr, DEV_IPV6, i + 10);
			nl_add_addr6(sock, net_devices[i].name, addr);
		}

		macaddr = DEV_MAC + ((i + 10ull) << 40);
		nl_device_change(sock, net_devices[i].name, 1, 0,
				 &macaddr, net_devices[i].macsize);
	}

	SAFE_CLOSE(sock);
}

static void create_tun(void)
{
	tunfd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
	if (tunfd == -1) {
#if SYZ_EXECUTOR
		fail("tun: can't open /dev/net/tun");
#else
		printf("tun: can't open /dev/net/tun: please enable CONFIG_TUN=y\n");
		printf("otherwise fuzzing or reproducing might not work as intended\n");
		return;
#endif
	}
	// Remap tun onto higher fd number to hide it from fuzzer and to keep
	// fd numbers stable regardless of whether tun is opened or not (also see kMaxFd).
	const int kTunFd = 240;
	if (dup2(tunfd, kTunFd) < 0)
		fail("dup2(tunfd, kTunFd) failed");
	close(tunfd);
	tunfd = kTunFd;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, TUN_IFACE, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_NAPI | IFF_NAPI_FRAGS;
	if (ioctl(tunfd, TUNSETIFF, (void*)&ifr) < 0) {
		// IFF_NAPI_FRAGS requires root, so try without it.
		ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
		if (ioctl(tunfd, TUNSETIFF, (void*)&ifr) < 0)
			fail("tun: ioctl(TUNSETIFF) failed");
	}
	// If IFF_NAPI_FRAGS is not supported it will be silently dropped,
	// so query the effective flags.
	if (ioctl(tunfd, TUNGETIFF, (void*)&ifr) < 0)
		fail("tun: ioctl(TUNGETIFF) failed");
	tun_frags_enabled = (ifr.ifr_flags & IFF_NAPI_FRAGS) != 0;
	debug("tun_frags_enabled=%d\n", tun_frags_enabled);

	// Disable IPv6 DAD, otherwise the address remains unusable until DAD completes.
	// Don't panic because this is an optional config.
	char sysctl[64];
	sprintf(sysctl, "/proc/sys/net/ipv6/conf/%s/accept_dad", TUN_IFACE);
	write_file(sysctl, "0");
	// Disable IPv6 router solicitation to prevent IPv6 spam.
	// Don't panic because this is an optional config.
	sprintf(sysctl, "/proc/sys/net/ipv6/conf/%s/router_solicitations", TUN_IFACE);
	write_file(sysctl, "0");
	// There seems to be no way to disable IPv6 MTD to prevent more IPv6 spam.

	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock == -1)
		fail("socket(AF_NETLINK) failed");

	netlink_add_addr4(sock, TUN_IFACE, LOCAL_IPV4);
	netlink_add_addr6(sock, TUN_IFACE, LOCAL_IPV6);
	uint64 macaddr = REMOTE_MAC;
	struct in_addr in_addr;
	inet_pton(AF_INET, REMOTE_IPV4, &in_addr);
	netlink_add_neigh(sock, TUN_IFACE, &in_addr, sizeof(in_addr), &macaddr, ETH_ALEN);
	struct in6_addr in6_addr;
	inet_pton(AF_INET6, REMOTE_IPV6, &in6_addr);
	netlink_add_neigh(sock, TUN_IFACE, &in6_addr, sizeof(in6_addr), &macaddr, ETH_ALEN);
	macaddr = LOCAL_MAC;
	netlink_device_change(sock, TUN_IFACE, true, 0, &macaddr, ETH_ALEN);
	close(sock);
}

static void create_network(void)
{
	create_network_devices();
}
