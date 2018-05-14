/*
 * Copyright (c) 2018 Richard Palethorpe <rpalethorp@suse.com>
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

#ifndef TST_PRCTL_H__
#define TST_PRCTL_H__

#include "config.h"
#include "tst_test.h"

#ifdef HAVE_SYS_PRCTL_H
# include "lapi/prctl.h"

void tst_drop_caps(int *caps, int count, int relaxed)
{
	int i;

	for (i = 0; i < count; i++) {
		TEST(prctl(PR_CAPBSET_DROP, caps[i]));
		if (TEST_RETURN < 0 && TEST_ERRNO == EPERM) {
			tst_res(TINFO | TTERRNO,
				"Can't drop capabilities because we do not have CAP_SETPCAP");
			break;
		} else if (TEST_RETURN < 0 && !relaxed && TEST_ERRNO == EINVAL) {
			tst_brk(TCONF | TTERRNO,
				"Capability %d is missing or else capabilities are disabled",
				caps[i]);
		} else if (TEST_RETURN < 0 && TEST_ERRNO == EINVAL) {
			tst_res(TINFO | TTERRNO,
				"Capability %d is missing or else capabilities are disabled",
				caps[i]);
		} else if (TEST_RETURN < 0) {
			tst_brk(TBROK | TTERRNO,
				"Unexpected error code returned by prctl when trying to drop %d",
				caps[i]);
		}
	}

	for (i = 0; i < count; i++) {
		TEST(prctl(PR_CAPBSET_READ, caps[i]));
		if (TEST_RETURN < 0 && TEST_ERRNO != EINVAL) {
			tst_brk(TBROK | TTERRNO,
				"Unexpected error code when reading capability %d",
				caps[i]);
		} else if (TEST_RETURN) {
			tst_brk(TCONF,
				"Can't drop capability %d, consider adding CAP_SETPCAP or removing %d",
				caps[i], caps[i]);
		}
	}
}

#else	/* HAVE_SYS_PRCTL_H */

void tst_drop_caps(int *caps, int count, int relaxed)
{
	tst_brk(TCONF, "Can't drop capabilities because sys/prctl.h is missing")
}

#endif	/* HAVE_SYS_PRCTL_H */
#endif	/* TST_PRCTL_H__ */
