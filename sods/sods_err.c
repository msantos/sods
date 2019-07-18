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

#ifndef HAVE_ERRX
#include <stdarg.h>

#include "sods.h"

void sds_err(int rv, char *fmt, ...) {
  va_list ap;

  (void)fprintf(stderr, "%s: ", SDS_PROGNAME);
  va_start(ap, fmt);
  (void)vfprintf(stderr, fmt, ap);
  va_end(ap);
  (void)fprintf(stderr, ": %s\n", strerror(errno));

  exit(rv);
}

void sds_errx(int rv, char *fmt, ...) {
  va_list ap;

  (void)fprintf(stderr, "%s: ", SDS_PROGNAME);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  (void)fprintf(stderr, "\n");

  exit(rv);
}

void sds_warn(char *fmt, ...) {
  va_list ap;

  (void)fprintf(stderr, "%s: ", SDS_PROGNAME);
  va_start(ap, fmt);
  (void)vfprintf(stderr, fmt, ap);
  va_end(ap);
  (void)fprintf(stderr, ": %s\n", strerror(errno));
}

void sds_warnx(char *fmt, ...) {
  va_list ap;

  (void)fprintf(stderr, "%s: ", SDS_PROGNAME);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  (void)fprintf(stderr, "\n");
}
#endif /* ! HAVE_ERRX */
