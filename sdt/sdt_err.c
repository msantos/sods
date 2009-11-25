/*
 * Socket over DNS client.
 *
 * Copyright (c) 2009 Michael Santos <michael.santos@gmail.com>
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
