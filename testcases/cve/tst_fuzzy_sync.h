/*
 * Copyright (c) 2017 Richard Palethorpe <rpalethorpe@suse.com>
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

#include <sys/time.h>
#include <time.h>

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

struct tst_fzsync_pair
{
	double avg_diff;
	double avg_diff_trgt;
	double avg_alpha;
	struct timespec a;
	struct timespec b;
	volatile long delay;
	long delay_inc;
	int update_gap;
};

static void tst_fzsync_pair_init(struct tst_fzsync_pair *pair)
{
	if (pair->avg_alpha == 0)
		pair->avg_alpha = 0.25;
	if (pair->delay_inc == 0)
		pair->delay_inc = 10;
	if (pair->update_gap == 0)
		pair->update_gap = 0xF;
}

static void tst_fzsync_pair_info(struct tst_fzsync_pair *pair)
{
	tst_res(TINFO, "avg_diff = %.5gns, delay = %05ld loops",
		pair->avg_diff, pair->delay);
}

static inline void tst_fzsync_delay_a(struct tst_fzsync_pair *pair)
{
	volatile long spin_delay = pair->delay;

	while(spin_delay > 0)
		spin_delay--;
}

static inline void tst_fzsync_delay_b(struct tst_fzsync_pair *pair)
{
	volatile long spin_delay = pair->delay;

	while(spin_delay < 0)
		spin_delay++;
}

static inline void tst_fzsync_time(struct timespec *t)
{
	clock_gettime(CLOCK_MONOTONIC_RAW, t);
}

static inline void tst_fzsync_time_a(struct tst_fzsync_pair *pair)
{
	tst_fzsync_time(&pair->a);
}

static inline void tst_fzsync_time_b(struct tst_fzsync_pair *pair)
{
	tst_fzsync_time(&pair->b);
}

static inline double tst_exp_moving_avg(double alpha, long sample, double prev_avg)
{
	return alpha * sample + (1.0 - alpha) * prev_avg;
}

static void tst_fzsync_pair_update(int loop_index, struct tst_fzsync_pair *pair)
{
	long diff;
	long inc = pair->delay_inc;
	long delay = pair->delay;
	double target = pair->avg_diff_trgt;
	double avg = pair->avg_diff;

	diff = pair->a.tv_nsec - pair->b.tv_nsec;
	avg = tst_exp_moving_avg(pair->avg_alpha, diff, avg);

	if (!(loop_index & pair->update_gap)) {
		if (avg > target)
			delay -= inc;
		else if (avg < target)
			delay += inc;
	}

	pair->avg_diff = avg;
	pair->delay = delay;
}
