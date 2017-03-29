#include <mqueue.h>
#include <stdarg.h>

#define TST_NO_DEFAULT_MAIN
#include "tst_test.h"
#include "tst_safe_posix_ipc.h"

mqd_t __attribute__((weak)) mq_open(const char *name __attribute__((unused)),
				    int oflag __attribute__((unused)), ...)
{
	tst_brk(TBROK, "mq_open() stub called!");
	return 0;
}

int safe_mq_open(const char *file, const int lineno, const char *pathname,
	int oflags, ...)
{
	va_list ap;
	int rval;
	mode_t mode;
	struct mq_attr *attr;

	va_start(ap, oflags);

	/* Android's NDK's mode_t is smaller than an int, which results in
	 * SIGILL here when passing the mode_t type.
	 */
#ifndef ANDROID
	mode = va_arg(ap, mode_t);
#else
	mode = va_arg(ap, int);
#endif

	attr = va_arg(ap, struct mq_attr *);

	va_end(ap);

	rval = mq_open(pathname, oflags, mode, attr);
	if (rval == -1) {
		tst_brk(TBROK | TERRNO, "%s:%d: mq_open(%s,%d,0%o,%p) failed",
			 file, lineno, pathname, oflags, mode, attr);
	}

	return rval;
}
