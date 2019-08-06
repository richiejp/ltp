// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2019 Richard Palethorpe <rpalethorpe@suse.com>
 *
 * Trivial Extended Berkeley Packet Filter (eBPF) test.
 *
 * Sanity check creating and updating maps.
 */

#include <limits.h>
#include <string.h>

#include "config.h"
#include "tst_test.h"
#include "lapi/bpf.h"

#define KEY_SZ 8
#define VAL_SZ 1024

struct map_type {
	uint32_t id;
	char *name;
};

static const struct map_type map_types[] = {
	{BPF_MAP_TYPE_HASH, "hash"},
	{BPF_MAP_TYPE_ARRAY, "array"}
};

static void *key;
static void *val0;
static void *val1;
static union bpf_attr *attr;

void run(unsigned int n)
{
	int fd, i;

	memset(attr, 0, sizeof(*attr));
	attr->map_type = map_types[n].id;
	attr->key_size = n == 0 ? KEY_SZ : 4;
	attr->value_size = VAL_SZ;
	attr->max_entries = 1;

	TEST(bpf(BPF_MAP_CREATE, attr, sizeof(*attr)));
	if (TST_RET == -1) {
		if (TST_ERR == EPERM) {
			tst_brk(TCONF | TTERRNO,
				"bpf() requires CAP_SYS_ADMIN on this system");
		} else {
			tst_brk(TFAIL | TTERRNO, "Failed to create %s map",
				map_types[n].name);
		}
	}
	tst_res(TPASS, "Created %s map", map_types[n].name);
	fd = TST_RET;

	if (n == 0)
		memcpy(key, "12345678", KEY_SZ);
	else
		memset(key, 0, 4);

	memset(attr, 0, sizeof(*attr));
	attr->map_fd = fd;
	attr->key = ptr_to_u64(key);
	attr->value = ptr_to_u64(val1);

	TEST(bpf(BPF_MAP_LOOKUP_ELEM, attr, sizeof(*attr)));
	if (n == 0) {
		if (TST_RET != -1 || TST_ERR != ENOENT) {
			tst_res(TFAIL | TTERRNO,
				"Empty hash map lookup should fail with ENOENT");
		} else {
			tst_res(TPASS | TTERRNO, "Empty hash map lookup");
		}
	} else if (TST_RET != -1) {
		for (i = 0;;) {
			if (*(char *) val1 != 0) {
				tst_res(TFAIL,
					"Preallocated array map val not zero");
			} else if (++i >= VAL_SZ) {
				tst_res(TPASS,
					"Preallocated array map lookup");
				break;
			}
		}
	} else {
		tst_res(TFAIL | TERRNO, "Prellocated array map lookup");
	}

	memset(attr, 0, sizeof(*attr));
	attr->map_fd = fd;
	attr->key = ptr_to_u64(key);
	attr->value = ptr_to_u64(val0);
	attr->flags = BPF_ANY;

	TEST(bpf(BPF_MAP_UPDATE_ELEM, attr, sizeof(*attr)));
	if (TST_RET == -1) {
		tst_brk(TFAIL | TTERRNO,
			"Update %s map element",
			map_types[n].name);
	} else {
		tst_res(TPASS,
			"Update %s map element",
			map_types[n].name);
	}

	memset(attr, 0, sizeof(*attr));
	attr->map_fd = fd;
	attr->key = ptr_to_u64(key);
	attr->value = ptr_to_u64(val1);

	TEST(bpf(BPF_MAP_LOOKUP_ELEM, attr, sizeof(*attr)));
	if (TST_RET == -1) {
		tst_res(TFAIL | TTERRNO,
			"%s map lookup missing",
			map_types[n].name);
	} else if (memcmp(val0, val1, (size_t) VAL_SZ)) {
		tst_res(TFAIL,
			"%s map lookup returned different value",
			map_types[n].name);
	} else {
		tst_res(TPASS, "%s map lookup", map_types[n].name);
	}

	SAFE_CLOSE(fd);
}

static struct tst_test test = {
	.tcnt = 2,
	.test = run,
	.min_kver = "3.18",
	.bufs = (struct tst_buffers []) {
		{&key, .size = KEY_SZ},
		{&val0, .size = VAL_SZ},
		{&val1, .size = VAL_SZ},
		{&attr, .size = sizeof(*attr)},
		{NULL},
	},
};
