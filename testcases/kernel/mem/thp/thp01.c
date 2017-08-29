/*
 * Copyright (C) 2011-2017  Red Hat, Inc.
 *
 * This program is free software;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 * the GNU General Public License for more details.
 */

/* Description:
 *
 * This is a reproducer of CVE-2011-0999, which fixed by mainline commit
 * a7d6e4ecdb7648478ddec76d30d87d03d6e22b31:
 *
 * "Transparent hugepages can only be created if rmap is fully
 * functional. So we must prevent hugepages to be created while
 * is_vma_temporary_stack() is true."
 *
 * It will cause a panic something like this, if the patch didn't get
 * applied:
 *
 * kernel BUG at mm/huge_memory.c:1260!
 * invalid opcode: 0000 [#1] SMP
 * last sysfs file: /sys/devices/system/cpu/cpu23/cache/index2/shared_cpu_map
 * ....
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "mem.h"
#include "tst_minmax.h"
#include "tst_safe_sysv_ipc.h"

#define ARGS_SZ	256

static int shm_id;
static char *args[ARGS_SZ];
static char *arg;
static long *arg_count;

static void thp_test(void)
{
	pid_t pid = SAFE_FORK();

	if (!arg_count)
		tst_brk(TBROK, "No shared memory");

	if (!pid) {
		args[*arg_count] = NULL;

		do {
			TEST(execvp("true", args));
			args[--(*arg_count)] = NULL;
		} while (*arg_count > 0 && TEST_ERRNO == E2BIG);

		tst_brk(TBROK | TTERRNO, "execvp(\"true\", ...)");
	}

	tst_reap_children();
	tst_res(TPASS, "system didn't crash, pass.");
}

static void setup(void)
{
	struct rlimit rl = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	int i;
	long arg_len;

	shm_id = SAFE_SHMGET(IPC_PRIVATE, sizeof(long),
				 IPC_CREAT | IPC_EXCL);
	arg_count = SAFE_SHMAT(shm_id, NULL, 0);

	arg_len = 32 * sysconf(_SC_PAGESIZE);
	arg = SAFE_MALLOC(arg_len);
	memset(arg, 'c', arg_len - 1);
	arg[arg_len - 1] = '\0';

	args[0] = "true";
	*arg_count = ARGS_SZ - 1;
	tst_res(TINFO, "Using %ld args of size %ld", *arg_count, arg_len);
	for (i = 1; i < *arg_count; i++)
		args[i] = arg;

	SAFE_SETRLIMIT(RLIMIT_STACK, &rl);
}

static void cleanup(void)
{
	if (arg)
		free(arg);
	if (arg_count)
		SAFE_SHMDT(arg_count);
	if (shm_id)
		SAFE_SHMCTL(shm_id, IPC_RMID, NULL);
}

static struct tst_test test = {
	.needs_root = 1,
	.forks_child = 1,
	.setup = setup,
	.cleanup = cleanup,
	.test_all = thp_test,
};
