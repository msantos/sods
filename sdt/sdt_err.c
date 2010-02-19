/*
 * Socket over DNS client.
 *
 * Copyright (c) 2009 Michael Santos <michael.santos@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef HAVE_ERRX
#include <stdarg.h>
#include <errno.h>

#include "sdt.h"

extern char *__progname;

    void
sdt_err(int rv, char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "%s: ", __progname);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, ": %s\n", strerror(errno));

    exit (rv);
}

    void
sdt_errx(int rv, char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "%s: ", __progname);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, "\n");

    exit (rv);
}

    void
sdt_warn(char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "%s: ", __progname);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, ": %s\n", strerror(errno));
}

    void
sdt_warnx(char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "%s: ", __progname);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, "\n");
}
#endif /* ! HAVE_ERRX */
