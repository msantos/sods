/* Copyright (c) 2009-2015, Michael Santos <michael.santos@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <signal.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/wait.h>

#define DS_VERSION     "0.3.0"

#define IS_ERR(x) do { \
    if ((x) == -1) { \
        err(EXIT_FAILURE, "%s", #x); \
    } \
} while (0)

#define IS_NULL(x) do { \
    if ((x) == NULL) { \
        err(EXIT_FAILURE, "%s", #x); \
    } \
} while (0)

#define TIMESTAMP() do { \
           char outstr[200]; \
           time_t t; \
           struct tm *tmp; \
 \
           t = time(NULL); \
           tmp = localtime(&t); \
           if (tmp == NULL) { \
               perror("localtime"); \
               exit(EXIT_FAILURE); \
           } \
 \
           if (strftime(outstr, sizeof(outstr), "%Y-%m-%d %H:%M:%S ", tmp) == 0) { \
               (void)fprintf(stderr, "strftime returned 0"); \
               exit(EXIT_FAILURE); \
           } \
 \
           (void)fprintf(stderr, "%s", outstr); \
} while (0)


#define VERBOSE(x, ...) do { \
    if (ss->verbose >= 4) { \
        TIMESTAMP(); \
    } \
    if (ss->verbose >= x) { \
        (void)fprintf (stderr, __VA_ARGS__); \
    } \
} while (0)

#ifndef HAVE_STRTONUM
long long strtonum(const char *numstr, long long minval, long long maxval,
        const char **errstrp);
#endif
