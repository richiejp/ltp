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
/*
 * Fuzzy Synchronisation - abreviated to fzsync
 *
 * This library is intended to help reproduce race conditions by providing two
 * thread synchronisation mechanisms. The first is a 'checkpoint' system where
 * each thread will wait indefinitely for the other to enter a checkpoint
 * before continuing. This is acheived by calling tst_fzsync_wait() and/or
 * tst_fzsync_wait_update() at the points you want to synchronise in each
 * thread.
 *
 * The second takes the form a of a delay which is calculated by measuring the
 * time difference between two points in each thread and comparing it to the
 * desired difference (default is zero). Using a delay allows you to
 * synchronise the threads at a point outside of your direct control
 * (e.g. inside the kernel) or just increase the accuracy for the first
 * mechanism. It is acheived using tst_fzsync_delay_{a,b}(),
 * tst_fzsync_time_{a,b}() and tst_fzsync[_wait_]update().
 *
 * For a usage example see testcases/cve/cve-2016-7117.c or just run
 * 'git grep tst_fuzzy_sync.h'
 */

#include <sys/time.h>
#include <time.h>
#include <math.h>
#include "tst_atomic.h"

#ifdef LTP_FZSYNC_USE_FUTEX
# include <sys/syscall.h>
# include <linux/futex.h>
#endif

#ifndef CLOCK_MONOTONIC_RAW
# define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

/**
 * struct tst_fzsync_pair - the state of a two way synchronisation
 * @avg_diff: The average time difference over multiple iterations
 * @avg_diff_trgt: The desired average time difference, defaults to 0
 * @avg_alpha: The rate at which old diff samples are forgotten,
 *             defaults to 0.25
 * @avg_dev: Absolute average deviation
 * @a: The time at which call site A was last passed
 * @b: The time at which call site B was last passed
 * @delay: The size of the delay, positive to delay A, negative to delay B
 * @delay_inc: The step size of a delay increment, defaults to 10
 * @update_gap: The number of iterations between recalculating the delay.
 *              Defaults to 0xF and must be of the form $2^n - 1$
 * @info_gap: The number of iterations between printing some statistics.
 *            Defaults to 0x7FFFF and must also be one less than a power of 2.
 * @entry: Used by fzsync_pair_wait()
 * @exit: Used by fzsync_pair_wait()
 *
 * This contains all the necessary state for synchronising two points A and
 * B. Where A is the time of an event in one process and B is the time of an
 * event in another process.
 */
struct tst_fzsync_pair {
	double avg_diff;
	double avg_diff_trgt;
	double avg_alpha;
	double avg_dev;
	struct timespec a;
	struct timespec b;
	long delay;
	long delay_inc;
	int update_gap;
	int info_gap;
	int entry;
	int exit;
#ifdef LTP_FZSYNC_USE_FUTEX
	int exit;
#endif
};

/**
 * TST_FZSYNC_PAIR_INIT - Default values for struct tst_fzysnc_pair
 */
#define TST_FZSYNC_PAIR_INIT {	\
	.avg_alpha = 0.25,	\
	.delay_inc = 1,	        \
	.update_gap = 0xF,	\
	.info_gap = 0x7FFFF     \
}

/**
 * tst_fzsync_pair_info - Print some synchronisation statistics
 */
static void tst_fzsync_pair_info(struct tst_fzsync_pair *pair)
{
	tst_res(TINFO,
		"avg_diff = %.0fns, avg_dev = %.0fns, delay = %05ld loops",
		pair->avg_diff, pair->avg_dev, pair->delay);
}

/**
 * tst_fzsync_delay_a - Perform spin delay for A, if needed
 *
 * Usually called just before the point you want to synchronise.
 */
static inline void tst_fzsync_delay_a(struct tst_fzsync_pair *pair)
{
	volatile long spin_delay = pair->delay;

	while (spin_delay > 0)
		spin_delay--;
}

/**
 * tst_fzsync_delay_b - Perform spin delay for B, if needed
 *
 * Usually called just before the point you want to synchronise.
 */
static inline void tst_fzsync_delay_b(struct tst_fzsync_pair *pair)
{
	volatile long spin_delay = pair->delay;

	while (spin_delay < 0)
		spin_delay++;
}

static inline void tst_fzsync_time(struct timespec *t)
{
	clock_gettime(CLOCK_MONOTONIC_RAW, t);
}

/**
 * tst_fzsync_time_a - Set A's time to now.
 *
 * Called at the point you want to synchronise.
 */
static inline void tst_fzsync_time_a(struct tst_fzsync_pair *pair)
{
	tst_fzsync_time(&pair->a);
}

/**
 * tst_fzsync_time_b - Set B's call time to now.
 *
 * Called at the point you want to synchronise.
 */
static inline void tst_fzsync_time_b(struct tst_fzsync_pair *pair)
{
	tst_fzsync_time(&pair->b);
}

/**
 * TST_EXP_MOVING_AVG - Exponential moving average
 * @alpha: The preference for recent samples over old ones.
 * @sample: The current sample
 * @prev_avg: The average of the all the previous samples
 *
 * Returns average including the current sample.
 */
#define TST_EXP_MOVING_AVG(alpha, sample, prev_avg)\
	(alpha * sample + (1.0 - alpha) * prev_avg)

/**
 * tst_fzsync_pair_update - Recalculate the delay
 * @loop_index: The i in "for(i = 0;..." or zero to ignore update_gap
 * @pair: The state necessary for calculating the delay
 *
 * This should be called at the end of each loop to update the average
 * measured time difference (between A and B) and update the delay. It is
 * assumed that A and B are less than a second apart.
 *
 * The values of update_gap, avg_alpha and delay_inc decide the speed at which
 * the algorithm approaches the optimum delay value and whether it is
 * stable. If your test is behaving strangely, it could be because this
 * algorithm is behaving chaotically and flip-flopping between large positve
 * and negative delay values. You can call tst_fzysync_pair_info every few
 * loops to check whether the average difference and delay values are stable.
 */
static void tst_fzsync_pair_update(int loop_index, struct tst_fzsync_pair *pair)
{
	long diff;
	long inc = pair->delay_inc;
	double target = pair->avg_diff_trgt;
	double avg = pair->avg_diff;

	if (pair->a.tv_sec > pair->b.tv_sec)
		pair->a.tv_nsec += 1000000000;
	else if (pair->a.tv_sec < pair->b.tv_sec)
		pair->b.tv_nsec += 1000000000;

	diff = pair->a.tv_nsec - pair->b.tv_nsec;
	avg = TST_EXP_MOVING_AVG(pair->avg_alpha, diff, avg);
	pair->avg_dev = TST_EXP_MOVING_AVG(pair->avg_alpha,
					   fabs(diff - avg),
					   pair->avg_dev);

	if (!(loop_index & pair->update_gap)) {
		if (avg > target)
			pair->delay -= inc;
		else if (avg < target)
			pair->delay += inc;
	}

	if (!(loop_index & pair->info_gap))
		tst_fzsync_pair_info(pair);

	pair->avg_diff = avg;
}

/**
 * tst_fzsync_pair_wait - Wait for the other thread
 *
 * Use this if you need an additional synchronisation point in a thread. See
 * tst_fzsync_pair_wait_update().
 *
 * Returns a non-zero value if the thread should continue otherwise the
 * calling thread should exit.
 */
static inline int tst_fzsync_pair_wait(struct tst_fzsync_pair *pair)
{
	int n = tst_atomic_add_return_(1, &pair->entry, LTP_ACQUIRE);

#ifndef LTP_FZSYNC_USE_FUTEX
	do {
		n = 2;
		tst_atomic_cmpxchg_(&pair->entry, &n, 0,
				    LTP_RELEASE, LTP_ACQUIRE);
	} while (n == 1);

	tst_atomic_add_return_(1, &pair->exit, LTP_ACQUIRE);
	do {
		n = 2;
		tst_atomic_cmpxchg_(&pair->exit, &n, 0,
				    LTP_RELEASE, LTP_ACQUIRE);
	} while (n == 1);

#else
	if (n == 1) {
		syscall(SYS_futex, &pair->entry, FUTEX_WAIT, 1, 0, 0);
	} else {
		n = 2;
		tst_atomic_cmpxchg_(&pair->entry, &n, 0,
				    LTP_RELEASE, LTP_ACQUIRE);
		syscall(SYS_futex, &pair->entry, FUTEX_WAKE, 1, 0, 0);
	}

	n = tst_atomic_add_return_(1, &pair->exit, LTP_ACQUIRE);
	if (n == 1) {
		syscall(SYS_futex, &pair->exit, FUTEX_WAIT, 1, 0, 0);
	} else {
		n = 2;
		tst_atomic_cmpxchg_(&pair->exit, &n, 0,
				    LTP_RELEASE, LTP_ACQUIRE);
		syscall(SYS_futex, &pair->exit, FUTEX_WAKE, 1, 0, 0);
	}
#endif
	return n < 3;
}

/**
 * tst_fzsync_pair_wait_update - Wait for the other thread and then recalculate
 *
 * This allows you to have two long running threads which wait for each other
 * every iteration. So each thread will exit this function at approximately
 * the same time. It also updates the delay values in a thread safe manner.
 *
 * You must call this function in both threads the same number of times each
 * iteration. So a call in one thread must match with a call in the
 * other. Make sure that calls to tst_fzsync_pair_wait() and
 * tst_fzsync_pair_wait_update() happen in the same order in each thread. That
 * is, make sure that a call to tst_fzsync_pair_wait_update() in one thread
 * corresponds to a call to tst_fzsync_pair_wait_update() in the other.
 *
 * Implementation notes: [ Because we expect to run in a loop, we have to
 * prevent the scenario where one thread 'overlaps' the other. For example
 * thread A may be spinning inside the wait function, when it is then put to
 * sleep by the kernel. Thread B then enters the wait function, resets the
 * atomic variable to zero and exits again. Then, before A is woken, B
 * re-enters the wait function on the next iteration and increments the atomic
 * variable to one.
 *
 * A then wakes and continues to spin because the atomic variable is set to
 * one. B is also spinning waiting for A to increment the atomic variable. In
 * order to prevent this we use two atomic variables; entry and exit. If one
 * thread begins to race ahead while the other is sleeping in the entry spin
 * state then it will transition to the exit spin state and stay there until
 * the other thread joins it.
 *
 * When setting the atomic variables to zero we use cmpxchg to prevent the
 * exit signal (the atomic variables are set to any value > 2) from being
 * overwritten. ]
 *
 * Returns a non-zero value if the calling thread should continue to loop. If
 * it returns zero then tst_fzsync_exit() has been called and you must exit
 * the thread.
 */
static inline int tst_fzsync_pair_wait_update(struct tst_fzsync_pair *pair)
{
	static int loop_index;
	int n = tst_atomic_add_return_(1, &pair->entry, LTP_ACQ_REL);

#ifndef LTP_FZSYNC_USE_FUTEX
	if (n == 2) {
		loop_index++;
		tst_fzsync_pair_update(loop_index, pair);
		tst_atomic_cmpxchg_(&pair->entry, &n, 0,
				    LTP_RELEASE, LTP_ACQUIRE);
	}

	do {
		n = tst_atomic_load_(&pair->entry, LTP_ACQUIRE);
	} while (n && n < 3);

	tst_atomic_add_return_(1, &pair->exit, LTP_ACQUIRE);
	do {
		n = 2;
		tst_atomic_cmpxchg_(&pair->exit, &n, 0,
				    LTP_RELEASE, LTP_ACQUIRE);
	} while (n == 1);
#else
	if (n == 2) {
		loop_index++;
		tst_fzsync_pair_update(loop_index, pair);
		tst_atomic_cmpxchg_(&pair->entry, &n, 0,
				    LTP_RELEASE, LTP_ACQUIRE);
		syscall(SYS_futex, &pair->entry, FUTEX_WAKE, 1, 0, 0);
	} else {
		syscall(SYS_futex, &pair->entry, FUTEX_WAIT, 1, 0, 0);
	}

	n = tst_atomic_add_return_(1, &pair->exit, LTP_ACQUIRE);
	if (n == 1) {
		syscall(SYS_futex, &pair->exit, FUTEX_WAIT, 1, 0, 0);
	} else {
		n = 2;
		tst_atomic_cmpxchg_(&pair->exit, &n, 0,
				    LTP_RELEASE, LTP_ACQUIRE);
		syscall(SYS_futex, &pair->exit, FUTEX_WAKE, 1, 0, 0);
	}
#endif
	return n < 3;
}

/**
 * tst_fzsync_pair_exit - Signal that the other thread should exit
 *
 * Causes tst_fzsync_pair_wait() and tst_fzsync_pair_wait_update() to return
 * 0.
 */
static inline void tst_fzsync_pair_exit(struct tst_fzsync_pair *pair)
{
	tst_atomic_store_(3, &pair->exit, LTP_RELEASE);
	tst_atomic_store_(3, &pair->entry, LTP_RELEASE);
}
