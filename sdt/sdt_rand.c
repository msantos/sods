/*
 * Socket over DNS client.
 *
 * Copyright (c) 2009 Michael Santos <michael.santos@gmail.com>
 *
 */

#ifndef HAVE_ARC4RANDOM
#include <sys/time.h>
#include <time.h>

#ifdef HAVE_SSL
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_SSL */
#endif /* ! HAVE_ARC4RANDOM */

#include "sdt.h"

    void
sdt_rand_init(void)
{
#ifndef HAVE_ARC4RANDOM
#ifndef HAVE_SSL
    struct timeval tv;

    gettimeofday(&tv, NULL);
    srandom(getpid() ^ ~getuid() ^ tv.tv_sec ^ tv.tv_usec);
#endif /* ! HAVE_SSL */
#endif /* ! HAVE_ARC4RANDOM */

    return;
}

#ifndef HAVE_ARC4RANDOM
#ifdef HAVE_SSL
    u_int32_t
sdt_rand(void)
{
    u_int32_t rnd = 0;

    if (RAND_pseudo_bytes( (u_char  *)&rnd, sizeof(u_int32_t)) == 0)
        errx(EXIT_FAILURE, "%s", ERR_error_string(ERR_get_error(), NULL));

    return (rnd);
}
#endif /* HAVE_SSL */
#endif /* ! HAVE_ARC4RANDOM */

