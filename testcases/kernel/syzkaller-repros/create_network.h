
#include <linux/if_ether.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/in6.h>
#include <linux/neighbour.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

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
		tst_res(TBROK, "nlmsg attribute overflow/bad nesting");

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

static void nl_add_device(int sock, const char* type, const char* name)
{
	struct ifinfomsg hdr;

	memset(&hdr, 0, sizeof(hdr));
	nlmsg_write_head(RTM_NEWLINK, NLM_F_EXCL | NLM_F_CREATE, &hdr, sizeof(hdr));
	if (name)
		nlmsg_write_attr(IFLA_IFNAME, name, strlen(name));
	nlmsg_push_attr(IFLA_LINKINFO);
	nlmsg_write_attr(IFLA_INFO_KIND, type, strlen(type));
	nlmsg_pop_attr();

	int err = nlmsg_send(sock);
	tst_res(TINFO, "netlink: adding device %s type %s: %s", name, type, strerror(err));

	(void)err;
}

static void create_network(void)
{
	int sock;
	unsigned i;

	if (unshare(CLONE_NEWNET))
		tst_brk(TBROK | TERRNO, "Failed to create new network namespace");

	sock = SAFE_SOCKET(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	for (i = 0; i < ARRAY_SIZE(net_devtypes); i++)
		nl_add_device(sock, net_devtypes[i].type, net_devtypes[i].name);

	SAFE_CLOSE(sock);
}
