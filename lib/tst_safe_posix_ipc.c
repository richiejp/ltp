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
