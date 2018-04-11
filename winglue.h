/*
 * Vanitygen, vanity bitcoin address generator
 * Copyright (C) 2011 <samr7@cs.washington.edu>
 *
 * Vanitygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * Vanitygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Vanitygen.  If not, see <http://www.gnu.org/licenses/>.
 */

#if !defined(__VG_WINGLUE_H__)
#define __VG_WINGLUE_H__

#include <tchar.h>
#include <time.h>
#include <windows.h>

#define INLINE
#define snprintf _snprintf

struct timezone;

int gettimeofday(struct timeval *tv, struct timezone *tz);
void timeradd(struct timeval *a, struct timeval *b, struct timeval *result);
void timersub(struct timeval *a, struct timeval *b, struct timeval *result);

extern TCHAR *optarg;
extern int optind;

int getopt(int argc, TCHAR *argv[], TCHAR *optstring);

#if (_MSC_FULL_VER < 190000000)
unsigned int count_processors(void);
#endif

#define PRSIZET "I"

static inline char *strtok_r(char *strToken, const char *strDelimit,
			     char **context) {
  return strtok_s(strToken, strDelimit, context);
}
#endif /* !defined (__VG_WINGLUE_H__) */
