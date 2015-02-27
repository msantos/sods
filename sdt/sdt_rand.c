/*
 * Socket over DNS client.
 *
 * Copyright (c) 2009-2015 Michael Santos <michael.santos@gmail.com>
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

#ifdef HAVE_URANDOM
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif /* HAVE_URANDOM */
#endif /* ! HAVE_ARC4RANDOM */

#include "sdt.h"

    uint32_t
sdt_arc4random(int fd)
{
#ifdef HAVE_ARC4RANDOM
    (void)fd;
    return arc4random();
#elif defined(HAVE_URANDOM)
    return sdt_rand(fd);
#else
    (void)fd;
    return random();
#endif
}

    int
sdt_rand_init(void)
{
    int fd = -2;

#ifdef HAVE_ARC4RANDOM
    /* Nothing to do */
#elif defined(HAVE_URANDOM)
    fd = open("/dev/urandom", O_RDONLY);

    if (fd < 0)
        err(EXIT_FAILURE, "open(/dev/urandom)");

    return fd;
#else
    struct timeval tv;

    IS_ERR(gettimeofday(&tv, NULL));
    srandom(getpid() ^ ~getuid() ^ tv.tv_sec ^ tv.tv_usec);
#endif

    return fd;
}

#ifndef HAVE_ARC4RANDOM
#ifdef HAVE_URANDOM
    u_int32_t
sdt_rand(int fd)
{
    u_int32_t rnd = 0;

    if (read(fd, &rnd, sizeof(rnd)) != sizeof(rnd))
        err(EXIT_FAILURE, "read(/dev/urandom)");

    return rnd;
}
#endif /* HAVE_URANDOM */
#endif /* ! HAVE_ARC4RANDOM */
