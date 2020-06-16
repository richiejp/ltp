// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 Richard Palethorpe <rpalethorpe@suse.com>
 */

#include <stdlib.h>
#include <stdio.h>

#include "tst_test.h"
#include "tst_safe_pthread.h"
#include "tst_fuzzy_sync.h"

#define HEADER "a_start,b_start,a_end,b_end\n"
#define RECORD_LEN 128

static char record_path[PATH_MAX];
static struct tst_option opts[] = {
	{"f", (char **)(&record_path), "-f	Path to record file"},
	{NULL, NULL, NULL}
};

static struct tst_fzsync_pair pair;
static int record_fd;
static char* record;
static volatile char last_wins;

static long long tons(struct timespec ts)
{
	return tst_ts_to_ns(tst_ts_from_timespec(ts));
}

static void setup(void)
{
	record_fd = SAFE_OPEN(record_path, O_WRONLY | O_CREAT | O_TRUNC);
	record = SAFE_MMAP(NULL, pair.exec_loops * RECORD_LEN,
			   PROT_WRITE, MAP_SHARED, record_fd, 0);

	memcpy(record, HEADER, strlen(HEADER));
	record += strlen(HEADER);
	tst_fzsync_pair_init(&pair);
}

static void *worker(void *v LTP_ATTRIBUTE_UNUSED)
{
	while (tst_fzsync_run_b(&pair)) {
		tst_fzsync_start_race_b(&pair);
		usleep(1);
		last_wins = 'B';
		tst_fzsync_end_race_b(&pair);
	}

	return NULL;
}

static void run(void)
{
	int c;

	tst_fzsync_pair_reset(&pair, worker);

	while (tst_fzsync_run_a(&pair)) {
		tst_fzsync_start_race_a(&pair);
		last_wins = 'A';
		tst_fzsync_end_race_a(&pair);

		*(record++) = last_wins;
		*(record++) = ',';
		c = snprintf(record, RECORD_LEN, "%lld,%lld,%lld,%lld",
			     tons(pair.a_start), tons(pair.b_start),
			     tons(pair.a_end), tons(pair.b_end));

		if (c > RECORD_LEN)
			tst_brk(TBROK, "Record truncated by %d", c - RECORD_LEN);

		record += c - 1;
		*(record++) = '\n';
	}

	tst_res(TPASS, "We made it to the end!");
}

static void cleanup(void)
{
	tst_fzsync_pair_cleanup(&pair);
}

static struct tst_test test = {
	.setup = setup,
	.options = opts,
	.cleanup = cleanup,
	.test_all = run,
};
