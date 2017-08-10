/*
 * Copyright (c) 2016 Cyril Hrubis <chrubis@suse.cz>
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

#ifndef TST_ATOMIC_H__
#define TST_ATOMIC_H__

#include "config.h"

#if HAVE_ATOMIC_MEMORY_MODEL != 1
#define LTP_RELAXED 0
#define LTP_CONSUME 1
#define LTP_ACQUIRE 2
#define LTP_RELEASE 3
#define LTP_ACQ_REL 4
#define LTP_SEQ_CST 5
#else
#define LTP_RELAXED __ATOMIC_RELAXED
#define LTP_CONSUME __ATOMIC_CONSUME
#define LTP_ACQUIRE __ATOMIC_ACQUIRE
#define LTP_RELEASE __ATOMIC_RELEASE
#define LTP_ACQ_REL __ATOMIC_ACQ_REL
#define LTP_SEQ_CST __ATOMIC_SEQ_CST
#endif

#if HAVE_ATOMIC_MEMORY_MODEL == 1
static inline int tst_atomic_add_return_(int i, int *v, int memorder)
{
	return __atomic_add_fetch(v, i, memorder);
}

static inline int tst_atomic_add_return(int i, int *v)
{
	return tst_atomic_add_return_(i, v, LTP_SEQ_CST);
}

static inline int tst_atomic_cmpxchg_(int *current, int *expected, int desired,
				      int success_memorder, int failure_memorder)
{
	return  __atomic_compare_exchange_n(current, expected, desired, 0,
					    success_memorder, failure_memorder);
}

static inline int tst_atomic_load_(int *v, int memorder)
{
	return __atomic_load_n(v, memorder);
}

static inline void tst_atomic_store_(int i, int *v, int memorder)
{
	__atomic_store_n(v, i, memorder);
}

#elif HAVE_SYNC_ADD_AND_FETCH == 1
static inline int tst_atomic_add_return(int i, int *v)
{
	return __sync_add_and_fetch(v, i);
}

static inline int tst_atomic_add_return_(int i, int *v,
					 int memorder LTP_ATTRIBUTE_UNUSED)
{
	return tst_atomic_add_return(i, v);
}

static inline int tst_atomic_cmpxchg_(int *current, int *expected, int desired,
				      int success_memorder LTP_ATTRIBUTE_UNUSED,
				      int failure_memorder LTP_ATTRIBUTE_UNUSED)
{
	int v = __sync_val_compare_and_swap(current, *expected, desired);

	if (v != *expected) {
		*expected = v;
		return 0;
	}

	return 1;
}

static inline int tst_atomic_load_(int *v, int memorder LTP_ATTRIBUTE_UNUSED)
{
	int ret;

	ret = *v;
	__sync_synchronize();
	return ret;
}

static inline void tst_atomic_store_(int i, int *v, int memorder LTP_ATTRIBUTE_UNUSED)
{
	__sync_synchronize();
	*v = i;
}

#elif defined(__i386__) || defined(__x86_64__)
static inline int tst_atomic_add_return(int i, int *v)
{
	int __ret = i;

	/*
	 * taken from arch/x86/include/asm/cmpxchg.h
	 */
	asm volatile ("lock; xaddl %0, %1\n"
		: "+r" (__ret), "+m" (*v) : : "memory", "cc");

	return i + __ret;
}

static inline int tst_atomic_add_return_(int i, int *v,
					 int memorder LTP_ATTRIBUTE_UNUSED)
{
	return tst_atomic_add_return(i, v);
}

static inline int tst_atomic_cmpxchg_(int *current, int *expected, int desired,
				      int success_memorder LTP_ATTRIBUTE_UNUSED,
				      int failure_memorder LTP_ATTRIBUTE_UNUSED)
{
	asm volatile("lock; cmpxchgl %2,%1"
		     : "=a" (*expected), "+m" (*current)
		     : "r" (desired), "0" (*expected)
		     : "memory");
	return *expected == desired;
}

static inline int tst_atomic_load_(int *v, int memorder LTP_ATTRIBUTE_UNUSED)
{
	int ret;

	asm volatile("" : : : "memory");
	ret = *v;
	asm volatile("" : : : "memory");

	return ret;
}

static inline void tst_atomic_store_(int i, int *v,
				     int memorder LTP_ATTRIBUTE_UNUSED)
{
	asm volatile("" : : : "memory");
	*v = i;
	asm volatile("" : : : "memory");
}

#elif defined(__powerpc__) || defined(__powerpc64__)
static inline int tst_atomic_add_return(int i, int *v)
{
	int t;

	/* taken from arch/powerpc/include/asm/atomic.h */
	asm volatile(
		"	sync\n"
		"1:	lwarx	%0,0,%2		# atomic_add_return\n"
		"	add %0,%1,%0\n"
		"	stwcx.	%0,0,%2 \n"
		"	bne-	1b\n"
		"	sync\n"
		: "=&r" (t)
		: "r" (i), "r" (v)
		: "cc", "memory");

	return t;
}

static inline int tst_atomic_add_return_(int i, int *v,
					 int memorder LTP_ATTRIBUTE_UNUSED)
{
	return tst_atomic_add_return(i, v);
}

static inline int tst_atomic_cmpxchg_(int *current, int *expected, int desired,
				      int success_memorder LTP_ATTRIBUTE_UNUSED,
				      int failure_memorder LTP_ATTRIBUTE_UNUSED)
{
	/* taken from arch/powerpc/include/asm/cmpxchg.h */
	asm volatile (
		"       sync\n"
		"1:     lwarx	%0,0,%2           # atomic_cmpxchg\n"
		"       cmpw	0,%0,%3\n"
		"       bne-	2f\n"
	        "       stwcx.	%4,0,%2\n"
		"       bne-	1b\n"
		"       sync\n"
		"2:"
		: "=&r" (*expected), "+m" (*current)
		: "r" (current), "r" (*expected), "r" (desired)
		: "cc", "memory");

	return *expected == desired;
}

static inline int tst_atomic_load_(int *v, int memorder LTP_ATTRIBUTE_UNUSED)
{
	int ret;

	asm volatile("sync\n" : : : "memory");
	ret = *v;
	asm volatile("sync\n" : : : "memory");

	return ret;
}

static inline void tst_atomic_store_(int i, int *v,
				     int memorder LTP_ATTRIBUTE_UNUSED)
{
	asm volatile("sync\n" : : : "memory");
	*v = i;
	asm volatile("sync\n" : : : "memory");
}

#elif defined(__s390__) || defined(__s390x__)

static inline int tst_atomic_add_return(int i, int *v)
{
	int old_val, new_val;

	/* taken from arch/s390/include/asm/atomic.h */
	asm volatile(
		"	l	%0,%2\n"
		"0:	lr	%1,%0\n"
		"	ar	%1,%3\n"
		"	cs	%0,%1,%2\n"
		"	jl	0b"
		: "=&d" (old_val), "=&d" (new_val), "+Q" (*v)
		: "d" (i)
		: "cc", "memory");

	return old_val + i;
}

static inline int tst_atomic_add_return_(int i, int *v,
					 int memorder LTP_ATTRIBUTE_UNUSED)
{
	return tst_atomic_add_return(i, v);
}

static inline int tst_atomic_cmpxchg_(int *current, int *expected, int desired,
				      int success_memorder LTP_ATTRIBUTE_UNUSED,
				      int failure_memorder LTP_ATTRIBUTE_UNUSED)
{
	asm volatile(
		"	cs	%[old],%[new],%[ptr]"
		: [old] "+d" (*expected), [ptr] "+Q" (*current)
		: [new] "d" (desired)
		: "memory");

	return *expected == desired;
}

static inline int tst_atomic_load_(int *v, int memorder LTP_ATTRIBUTE_UNUSED)
{
	int ret;

	asm volatile("" : : : "memory");
	ret = *v;
	asm volatile("" : : : "memory");

	return ret;
}

static inline void tst_atomic_store_(int i, int *v,
				     int memorder LTP_ATTRIBUTE_UNUSED)
{
	asm volatile("" : : : "memory");
	*v = i;
	asm volatile("" : : : "memory");
}

#elif defined(__arc__)

/*ARCv2 defines the smp barriers */
#ifdef __ARC700__
#define smp_mb()
#else
#define smp_mb()	asm volatile("dmb 3\n" : : : "memory")
#endif

static inline int tst_atomic_add_return(int i, int *v)
{
	unsigned int val;

	smp_mb();

	asm volatile(
		"1:	llock   %[val], [%[ctr]]	\n"
		"	add     %[val], %[val], %[i]	\n"
		"	scond   %[val], [%[ctr]]	\n"
		"	bnz     1b			\n"
		: [val]	"=&r"	(val)
		: [ctr]	"r"	(v),
		  [i]	"ir"	(i)
		: "cc", "memory");

	smp_mb();

	return val;
}

#elif defined (__aarch64__)
static inline int tst_atomic_add_return(int i, int *v)
{
	unsigned long tmp;
	int result;

	__asm__ __volatile__(
"       prfm    pstl1strm, %2	\n"
"1:     ldaxr 	%w0, %2		\n"
"       add	%w0, %w0, %w3	\n"
"       stlxr	%w1, %w0, %2	\n"
"       cbnz	%w1, 1b		\n"
"       dmb ish			\n"
	: "=&r" (result), "=&r" (tmp), "+Q" (*v)
	: "Ir" (i)
	: "memory");

	return result;
}

static inline int tst_atomic_add_return_(int i, int *v,
					 int memorder LTP_ATTRIBUTE_UNUSED)
{
	return tst_atomic_add_return(i, v);
}

static inline int tst_atomic_cmpxchg_(int *current, int *expected, int desired,
				      int success_memorder LTP_ATTRIBUTE_UNUSED,
				      int failure_memorder LTP_ATTRIBUTE_UNUSED)
{
	unsigned long tmp;

	/* Taken from arch/arm64/include/asm/atomic_ll_sc.h */
	asm volatile("//atomic_cmpxchg                      \n"
		"	prfm	pstl1strm,  %[v]            \n"
		"1:	ldaxr	%w[oldval], %[v]            \n"
		"	eor	%w[tmp], %w[oldval], %w[old]\n"
		"	cbnz	%w[tmp], 2f                 \n"
		"	stlxr   %w[tmp], %w[new], %[v]      \n"
		"	cbnz	%w[tmp], 1b                 \n"
		"	dmb ish                             \n"
		"2:"
	: [tmp] "=&r" (tmp), [oldval] "=&r" (*expected),
	  [v] "+Q" (*(unsigned long *)current)
	: [old] "Kr" (*expected), [new] "r" (desired)
	: "memory");

	return *expected == desired;
}

static inline int tst_atomic_load_(int *v, int memorder LTP_ATTRIBUTE_UNUSED)
{
	int ret;
	unsigned long tmp;

	asm volatile("//atomic_load			\n"
		"	prfm	pstl1strm,  %[v]	\n"
		"1:	ldaxr	%w[ret], %[v]		\n"
		"	stlxr   %w[tmp], %w[ret], %[v]\n"
		"	cbnz    %w[tmp], 1b		\n"
		"	dmb ish				\n"
		: [tmp] "=&r" (tmp), [ret] "=&r" (ret), [v] "+Q" (*v)
		: : "memory");

	return ret;
}

static inline void tst_atomic_store_(int i, int *v,
				    int memorder LTP_ATTRIBUTE_UNUSED)
{
	unsigned long tmp;

	asm volatile("//atomic_store			\n"
		"	prfm	pstl1strm, %[v]		\n"
		"1:	ldaxr	%w[tmp], %[v]		\n"
		"	stlxr   %w[tmp], %w[i], %[v]	\n"
		"	cbnz    %w[tmp], 1b		\n"
		"	dmb ish				\n"
		: [tmp] "=&r" (tmp), [v] "+Q" (*v)
		: [i] "r" (i)
		: "memory");
}

#elif defined(__sparc__) && defined(__arch64__)
static inline int tst_atomic_add_return_(int i, int *v,
					 int memorder LTP_ATTRIBUTE_UNUSED)
{
	int ret, tmp;

	/* Based on arch/sparc/lib/atomic_64.S */
	asm volatile("/*atomic_add_return*/		\n"
		"1:	ldsw	[%[v]], %[ret];		\n"
		"	add	%[ret], %[i], %[tmp];	\n"
		"	cas	[%[v]], %[ret], %[tmp];	\n"
		"	cmp	%[ret], %[tmp];		\n"
		"	bne,pn	%%icc, 1b;		\n"
		"	nop;				\n"
		"	add	%[ret], %[i], %[ret];	\n"
		: [ret] "=r&" (ret), [tmp] "=r&" (tmp)
		: [i] "r" (i), [v] "r" (v)
		: "memory", "cc");

	return ret;
}

static inline int tst_atomic_add_return(int i, int *v)
{
	return tst_atomic_add_return_(i, v, LTP_SEQ_CST);
}

static inline int tst_atomic_cmpxchg_(int *current, int *expected, int desired,
				      int success_memorder LTP_ATTRIBUTE_UNUSED,
				      int failure_memorder LTP_ATTRIBUTE_UNUSED)
{
	/* Based on arch/sparc/include/asm/cmpxchg_64.h */
	asm volatile(
		"cas [%[current]], %[expected], %[desired]"
		: [desired] "+&r" (desired)
		: "[desired]" (desired),
		  [current] "r" (current),
		  [expected] "r" (*expected)
		: "memory");

	/* Unlike x86, [desired] is set/swapped with [*current] */
	if (*expected != desired) {
		*expected = desired;
		return 0;
	}

	return 1;
}

static inline int tst_atomic_load_(int *v, int memorder LTP_ATTRIBUTE_UNUSED)
{
	int ret;

	/* See arch/sparc/include/asm/barrier_64.h */
	asm volatile("" : : : "memory");
	ret = *v;
	asm volatile("" : : : "memory");

	return ret;
}

static inline void tst_atomic_store_(int i, int *v,
				     int memorder LTP_ATTRIBUTE_UNUSED)
{
	asm volatile("" : : : "memory");
	*v = i;
	asm volatile("" : : : "memory");
}

#else /* HAVE_SYNC_ADD_AND_FETCH == 1 */
# error Your compiler does not provide __atomic_add_fetch, __sync_add_and_fetch \
        and an LTP implementation is missing for your architecture.
#endif

static inline int tst_atomic_inc(int *v)
{
	return tst_atomic_add_return(1, v);
}

static inline int tst_atomic_dec(int *v)
{
	return tst_atomic_add_return(-1, v);
}

static inline int tst_atomic_cmpxchg(int *current, int *expected, int desired)
{
	return tst_atomic_cmpxchg_(current, expected, desired,
				  LTP_SEQ_CST, LTP_SEQ_CST);
}

static inline int tst_atomic_load(int *v)
{
	return tst_atomic_load_(v, LTP_SEQ_CST);
}

static inline void tst_atomic_store(int i, int *v)
{
	tst_atomic_store_(i, v, LTP_SEQ_CST);
}

#endif	/* TST_ATOMIC_H__ */
