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
 * A basic regression test for tst_atomic_{load,store} and
 * tst_atomic_cmpxchg. Also provides a limited check that atomic stores and
 * loads order non-atomic memory accesses. That is, we are checking that they
 * implement memory fences or barriers.
 *
 * Many architectures/machines will still pass the test even if you remove the
 * atomic functions. X86 in particular has strong memory ordering by default
 * so that should always pass (if you use volatile). However Aarch64
 * (Raspberry Pi 3 Model B) has been observed to fail without the atomic
 * functions.
 *
 * A failure can occur if an update to seq_n is not made globally visible by
 * the time the next thread needs to use it.
 */

#include <stdint.h>
#include <pthread.h>
#include "tst_test.h"
#include "tst_atomic.h"

#define THREADS 64
#define FILLER (1 << 20)

/* Uncomment these to see what happens without atomics. To prevent the compiler
 * from removing/reording atomic and seq_n, mark them as volatile.
 */
/* #define tst_atomic_load(v) (*(v)) */
/* #define tst_atomic_store(i, v) *(v) = (i) */

struct block {
	int seq_n;
	intptr_t id;
	intptr_t filler[FILLER];
};

static int atomic;
static int *seq_n;
static struct block *m;

static void *worker_load_store(void *_id)
{
	intptr_t id = (intptr_t)_id, i;

	for (i = (intptr_t)tst_atomic_load(&atomic);
	     i != id;
	     i = (intptr_t)tst_atomic_load(&atomic))
		;

	(m + (*seq_n))->id = id;
	*seq_n += 1;
	tst_atomic_store((int)i + 1, &atomic);

	return NULL;
}

static void *worker_cmpxchg(void *_id)
{
	intptr_t id = (intptr_t)_id;
	int i;

	do {
		i = (int)id;
		tst_atomic_cmpxchg(&atomic, &i, (int)id);
	} while (i != id);

	(m + (*seq_n))->id = id;
	*seq_n += 1;

	do {
		i = (int)id;
		tst_atomic_cmpxchg(&atomic, &i, (int)id + 1);
	} while (i != id);

	return NULL;
}

static void *cache_ruiner(void *vp LTP_ATTRIBUTE_UNUSED)
{
	intptr_t i = 0, j;
	struct block *cur = m;

	tst_res(TINFO, "cache ruiner started");
	while (tst_atomic_load(&atomic) > 0) {
		for (j = 0; j < FILLER; j++)
			cur->filler[j] = j;

		if (i < THREADS - 1) {
			cur = m + (++i);
		} else {
			i = 0;
			cur = m;
		}
	}

	return NULL;
}

static void do_test(unsigned int tcnt)
{
	intptr_t i, id;
	pthread_t threads[THREADS + 1];
	void *(*worker)(void *);

	atomic = 0;
	m = (struct block *)SAFE_MMAP(NULL, sizeof(*m) * THREADS,
				      PROT_READ | PROT_WRITE,
				      MAP_PRIVATE | MAP_ANONYMOUS,
				      -1, 0);
	seq_n = &((m + THREADS / 2)->seq_n);

	if (tcnt)
		worker = worker_cmpxchg;
	else
		worker = worker_load_store;

	pthread_create(threads+THREADS, NULL, cache_ruiner, NULL);
	for (i = THREADS - 1; i >= 0; i--)
		pthread_create(threads+i, NULL, worker, (void *)i);

	for (i = 0; i < THREADS; i++) {
		tst_res(TINFO, "Joining thread %li", i);
		pthread_join(threads[i], NULL);
	}
	tst_atomic_store(-1, &atomic);
	pthread_join(*(threads+THREADS), NULL);

	tst_res(TINFO, "Expected\tFound");
	for (i = 0; i < THREADS; i++) {
		id = (m + i)->id;
		if (id != i)
			tst_res(TFAIL, "%d\t\t%d", (int)i, (int)id);
		else
			tst_res(TPASS, "%d\t\t%d", (int)i, (int)id);
	}

	SAFE_MUNMAP(m, sizeof(*m) * THREADS);
}

static struct tst_test test = {
	.test = do_test,
	.tcnt = 2,
};
