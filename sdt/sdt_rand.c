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

