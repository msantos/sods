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
#ifndef HAVE_ARC4RANDOM
#include <sys/time.h>
#include <time.h>

#ifdef HAVE_URANDOM
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif /* HAVE_URANDOM */
#endif /* ! HAVE_ARC4RANDOM */

#include "sdt.h"

uint32_t sdt_arc4random(int fd) {
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

int sdt_rand_init(void) {
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
u_int32_t sdt_rand(int fd) {
  u_int32_t rnd = 0;

  if (read(fd, &rnd, sizeof(rnd)) != sizeof(rnd))
    err(EXIT_FAILURE, "read(/dev/urandom)");

  return rnd;
}
#endif /* HAVE_URANDOM */
#endif /* ! HAVE_ARC4RANDOM */
