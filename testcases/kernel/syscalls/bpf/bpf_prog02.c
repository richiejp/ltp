// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2019 Richard Palethorpe <rpalethorpe@suse.com>
 *
 * Check if eBPF can do arithmetic with 64bits. This targets a specific
 * regression which only effects unprivileged users who are subject to extra
 * pointer arithmetic checks during verification.
 *
 * https://new.blog.cloudflare.com/ebpf-cant-count/
 *
 * This test is very similar in structure to bpf_prog01 which is better
 * annotated.
 */

#include <limits.h>
#include <string.h>
#include <stdio.h>

#include "config.h"
#include "tst_test.h"
#include "lapi/socket.h"
#include "lapi/bpf.h"

#define A64INT (((uint64_t)1) << 31)

const char MSG[] = "Ahoj!";
static char *msg;

static char *log;
static uint32_t *key;
static uint64_t *val;
static union bpf_attr *attr;

int load_prog(int fd)
{
	struct bpf_insn *prog;
	struct bpf_insn insn[] = {
		BPF_MOV64_IMM(BPF_REG_6, 1),            /* r6 = 1 */

		BPF_LD_MAP_FD(BPF_REG_1, fd),	        /* r1 = &fd */
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),   /* r2 = fp */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),  /* r2 = r2 - 8 */
		BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),    /* *r2 = 0 */
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 17), /* if(!r0) goto exit */
		BPF_MOV64_REG(BPF_REG_3, BPF_REG_0),    /* r3 = r0 */
		BPF_LD_IMM64(BPF_REG_4, A64INT),        /* r4 = 2^32 */
		BPF_ALU64_REG(BPF_ADD, BPF_REG_4, BPF_REG_6), /* r4 += r6 */
		BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_4, 0), /* *r3 = r4 */

		BPF_LD_MAP_FD(BPF_REG_1, fd),	        /* r1 = &fd */
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),   /* r2 = fp */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),  /* r2 = r2 - 8 */
		BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),    /* *r2 = 1 */
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 5),  /* if(!r0) goto exit */
		BPF_MOV64_REG(BPF_REG_3, BPF_REG_0),    /* r3 = r0 */
		BPF_LD_IMM64(BPF_REG_4, A64INT),        /* r4 = 2^32 */
		BPF_ALU64_REG(BPF_SUB, BPF_REG_4, BPF_REG_6), /* r4 -= r6 */
		BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_4, 0), /* *r3 = r4 */

		BPF_MOV64_IMM(BPF_REG_0, 0),            /* r0 = 0 */
		BPF_EXIT_INSN(),		        /* return r0 */
	};

	/* Leaks memory when -i is specified */
	prog = tst_alloc(sizeof(insn));
	memcpy(prog, insn, sizeof(insn));

	memset(attr, 0, sizeof(*attr));
	attr->prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr->insns = ptr_to_u64(prog);
	attr->insn_cnt = ARRAY_SIZE(insn);
	attr->license = ptr_to_u64("GPL");
	attr->log_buf = ptr_to_u64(log);
	attr->log_size = BUFSIZ;
	attr->log_level = 1;

	TEST(bpf(BPF_PROG_LOAD, attr, sizeof(*attr)));
	if (TST_RET == -1) {
		if (log[0] != 0) {
			tst_res(TINFO, "Verification log:");
			fputs(log, stderr);
			tst_brk(TBROK | TTERRNO, "Failed verification");
		} else {
			tst_brk(TBROK | TTERRNO, "Failed to load program");
		}
	}

	return TST_RET;
}

void setup(void)
{
	memcpy(msg, MSG, sizeof(MSG));
}

void run(void)
{
	int map_fd, prog_fd;
	int sk[2];

	memset(attr, 0, sizeof(*attr));
	attr->map_type = BPF_MAP_TYPE_ARRAY;
	attr->key_size = 4;
	attr->value_size = 8;
	attr->max_entries = 2;

	TEST(bpf(BPF_MAP_CREATE, attr, sizeof(*attr)));
	if (TST_RET == -1) {
		if (TST_ERR == EPERM) {
			tst_brk(TCONF | TTERRNO,
				"bpf() requires CAP_SYS_ADMIN on this system");
		} else {
			tst_brk(TBROK | TTERRNO, "Failed to create array map");
		}
	}
	map_fd = TST_RET;

	prog_fd = load_prog(map_fd);

	SAFE_SOCKETPAIR(AF_UNIX, SOCK_DGRAM, 0, sk);
	SAFE_SETSOCKOPT(sk[1], SOL_SOCKET, SO_ATTACH_BPF,
			&prog_fd, sizeof(prog_fd));

	SAFE_WRITE(1, sk[0], msg, sizeof(MSG));

	memset(attr, 0, sizeof(*attr));
	attr->map_fd = map_fd;
	attr->key = ptr_to_u64(key);
	attr->value = ptr_to_u64(val);
	*key = 0;

	TEST(bpf(BPF_MAP_LOOKUP_ELEM, attr, sizeof(*attr)));
	if (TST_RET == -1) {
		tst_res(TFAIL | TTERRNO, "array map lookup");
	} else if (*val != A64INT + 1) {
		tst_res(TFAIL,
			"val = %lu, but should be val = %lu + 1",
			*val, A64INT);
        } else {
	        tst_res(TPASS, "val = %lu + 1", A64INT);
	}

	*key = 1;

	TEST(bpf(BPF_MAP_LOOKUP_ELEM, attr, sizeof(*attr)));
	if (TST_RET == -1) {
		tst_res(TFAIL | TTERRNO, "array map lookup");
	} else if (*val != A64INT - 1) {
		tst_res(TFAIL,
			"val = %lu, but should be val = %lu - 1",
			*val, A64INT);
        } else {
	        tst_res(TPASS, "val = %lu - 1", A64INT);
	}

	SAFE_CLOSE(prog_fd);
	SAFE_CLOSE(map_fd);
	SAFE_CLOSE(sk[0]);
	SAFE_CLOSE(sk[1]);
}

static struct tst_test test = {
	.setup = setup,
	.test_all = run,
	.min_kver = "3.18",
	.bufs = (struct tst_buffers []) {
		{&key, .size = sizeof(*key)},
		{&val, .size = sizeof(*val)},
		{&log, .size = BUFSIZ},
		{&attr, .size = sizeof(*attr)},
		{&msg, .size = sizeof(MSG)},
		{NULL},
	}
};
