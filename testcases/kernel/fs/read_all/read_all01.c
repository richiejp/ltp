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
 * Perform a small read on every file in a directory tree.
 *
 * Useful for testing file systems like proc, sysfs and debugfs or anything
 * which exposes a file like API so long as it respects O_NONBLOCK. This test
 * is not concerned if a particular file in one of these file systems conforms
 * exactly to its specific documented behavior. Just whether reading from that
 * file causes a serious error such as a NULL pointer dereference.
 *
 * It is not required to run this as root, but test coverage will be much
 * higher with full privileges.
 *
 * The reads are preformed by worker processes which are given file paths by a
 * single parent process. The parent process recursively scans a given
 * directory and passes the file paths it finds to the child processes using
 * some shared memory. The test will use a maximum of 15 processes, depending
 * on the number of CPU cores available, under the assumption that while
 * parallelism is good we don't want to spend too much time creating
 * processes, distributing data and waiting for locks.
 *
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <fnmatch.h>
#include <semaphore.h>
#include <ctype.h>

#include "tst_test.h"

#define QUEUE_SIZE 16384
#define BUFFER_SIZE 1024
#define MAX_PATH 4096

struct queue {
	sem_t sem;
	int front;
	int back;
	char data[QUEUE_SIZE];
};

struct worker {
	pid_t pid;
	struct queue *q;
};

static char *verbose;
static char *quite;
static char *root_dir;
static char *exclude;
static char *str_repeat;
static int repeat = 1;
static long worker_count;
static struct worker *workers;

static struct tst_option options[] = {
	{"v", &verbose,
	 "-v       Print information about successful reads"},
	{"q", &quite,
	 "-q       Don't print file read or open errors"},
	{"d:", &root_dir,
	 "-d path  Path to the directory to read from, defaults to /sys"},
	{"e:", &exclude,
	 "-e pattern Ignore files which match an 'extended' pattern, see fnmatch(3)"},
	{"r:", &str_repeat,
	 "-r count The number of times to read each file within one test iteration"},
	{NULL, NULL, NULL}
};

static int queue_pop(struct queue *q, char *buf)
{
	int i = q->front, j = 0;

	sem_wait(&q->sem);

	if (!q->data[i])
		return 0;

	while (q->data[i]) {
		buf[j] = q->data[i];

		if (++j >= BUFFER_SIZE - 1)
			tst_brk(TBROK, "Buffer is too small for path");
		if (++i >= QUEUE_SIZE)
			i = 0;
	}

	buf[j] = '\0';
	q->front = i + 1;

	return 1;
}

static int queue_push(struct queue *q, const char *buf)
{
	int i = q->back, j = 0;

	while (buf[j]) {
		q->data[i] = buf[j];

		++j;
		if (++i >= QUEUE_SIZE)
			i = 0;
		if (i == q->front)
			return 0;
	}
	q->data[i] = '\0';

	q->back = i + 1;
	sem_post(&q->sem);

	return 1;
}

static struct queue *queue_init(void)
{
	struct queue *q = SAFE_MMAP(NULL, sizeof(*q),
				    PROT_READ | PROT_WRITE,
				    MAP_SHARED | MAP_ANONYMOUS,
				    0, 0);

	sem_init(&q->sem, 1, 0);
	q->front = 0;
	q->back = 0;

	return q;
}

static void queue_destroy(struct queue *q, int is_worker)
{
	if (is_worker)
		sem_destroy(&q->sem);
	SAFE_MUNMAP(q, sizeof(*q));
}

static void sanitize_str(char *buf, ssize_t count)
{
	int i;

	for (i = 0; i < MIN(count, 20); i++) {
		if (!isprint(buf[i]))
			buf[i] = ' ';
	}

	if (count <= 20) {
		if (buf[count - 1] == '\n')
			buf[count - 1] = '\0';
		else
			buf[count] = '\0';
	} else
		strcpy(buf + 20, "...");
}

static void read_test(const char *path)
{
	char buf[BUFFER_SIZE];
	int fd;
	ssize_t count;

	if (exclude && !fnmatch(exclude, path, FNM_EXTMATCH)) {
		if (verbose)
			tst_res(TINFO, "Ignoring %s", path);
		return;
	}

	if (verbose)
		tst_res(TINFO, "%s(%s)", __func__, path);

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0 && !quite) {
		tst_res(TINFO | TERRNO, "open(%s)", path);
		return;
	} else if (fd < 0)
		return;

	count = read(fd, buf, sizeof(buf) - 1);
	if (count > 0 && verbose) {
		sanitize_str(buf, count);
		tst_res(TINFO, "read(%s, buf) = %ld, buf = %s",
			path, count, buf);

	} else if (!count && verbose)
		tst_res(TINFO, "read(%s) = EOF", path);
	else if (count < 0 && !quite)
		tst_res(TINFO | TERRNO, "read(%s)", path);

	SAFE_CLOSE(fd);
}

static int worker_run(struct worker *self)
{
	int ret;
	char buf[BUFFER_SIZE];
	struct sigaction term_sa = {
		.sa_handler = SIG_IGN,
		.sa_flags = 0,
	};
	struct queue *q = self->q;

	sigaction(SIGTTIN, &term_sa, NULL);

	for (ret = queue_pop(q, buf); ret; ret = queue_pop(q, buf)) {
		read_test(buf);
	}

	queue_destroy(q, 1);

	return 0;
}

static void spawn_workers(void)
{
	int i;
	struct worker *wa = workers;

	bzero(workers, worker_count * sizeof(*workers));

	for (i = 0; i < worker_count; i++) {
		wa[i].q = queue_init();
		wa[i].pid = SAFE_FORK();
		if (!wa[i].pid) {
			exit(worker_run(wa + i));
		}
	}
}

static void stop_workers(void)
{
	const char stop_code[1] = { '\0' };
	int i;

	if (!workers)
		return;

	for (i = 0; i < worker_count; i++) {
		if (workers[i].q)
			queue_push(workers[i].q, stop_code);
	}

	for (i = 0; i < worker_count; i++) {
		if (workers[i].q) {
			queue_destroy(workers[i].q, 0);
			workers[i].q = 0;
		}
	}
}

static void sched_work(const char *path)
{
	static long cur;
	int push_attempts, i;

	for (i = 0; i < repeat; i++) {
		push_attempts = 0;
		while (!queue_push(workers[cur].q, path)) {
			cur++;
			push_attempts++;
			if (cur >= worker_count)
				cur = 0;
			if (push_attempts > worker_count) {
				tst_brk(TINFO, "Worker queues are all full");
				usleep(100);
				push_attempts = 0;
			}
		}
	}
}

static void setup(void)
{
	if (tst_parse_int(str_repeat, &repeat, 1, INT_MAX)) {
		tst_brk(TBROK,
			"Invalid repeat (-r) argument: '%s'", str_repeat);
	}
	worker_count = MIN(MAX(SAFE_SYSCONF(_SC_NPROCESSORS_ONLN) - 1, 1), 15);
	workers = SAFE_MALLOC(worker_count * sizeof(*workers));
}

static void cleanup(void)
{
	stop_workers();
	free(workers);
}

static void visit_dir(const char *path)
{
	DIR *dir;
	struct dirent *dent;
	struct stat dent_st;
	char dent_path[MAX_PATH];

	dir = opendir(path);
	if (!dir) {
		tst_res(TINFO | TERRNO, "opendir(%s)", path);
		return;
	}

	for (dent = SAFE_READDIR(dir); dent; dent = SAFE_READDIR(dir)) {
		if (!strcmp(dent->d_name, ".") ||
		    !strcmp(dent->d_name, ".."))
			continue;

		snprintf(dent_path, MAX_PATH,
			 "%s/%s", path, dent->d_name);
		if (dent->d_type != DT_UNKNOWN) {
			switch (dent->d_type) {
			case DT_DIR:
				visit_dir(dent_path);
				break;
			case DT_LNK:
				break;
			default:
				sched_work(dent_path);
			}
		} else {
			SAFE_LSTAT(dent_path, &dent_st);
			switch (dent_st.st_mode & S_IFMT) {
			case S_IFDIR:
				visit_dir(dent_path);
				break;
			case S_IFLNK:
				break;
			default:
				sched_work(dent_path);
			}
		}
	}

	SAFE_CLOSEDIR(dir);
}

static void run(void)
{
	spawn_workers();
	visit_dir(root_dir);
	stop_workers();

	tst_reap_children();
	tst_res(TPASS, "Finished reading files");
}

static struct tst_test test = {
	.options = options,
	.setup = setup,
	.cleanup = cleanup,
	.test_all = run,
	.forks_child = 1,
};

