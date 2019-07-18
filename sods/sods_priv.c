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
#include <grp.h>
#include <pwd.h>

#include "sods.h"

#define SDS_USER "nobody"
#define SDS_GROUP "nogroup"

#define SDS_CHROOT "/var/chroot/sods"

#define SETVAR(x, y) ((x) = ((x) == NULL ? (y) : (x)))

void sds_priv_daemon(SDS_STATE *ss);
int sds_priv_drop(SDS_STATE *ss);

int sds_priv_init(SDS_STATE *ss) {
  if (ss->daemon == 1)
    sds_priv_daemon(ss);
  return sds_priv_drop(ss);
}

void sds_priv_daemon(SDS_STATE *ss) {
  openlog(SDS_PROGNAME, LOG_NDELAY, LOG_DAEMON);
  IS_ERR(daemon(0, 0));
}

int sds_priv_drop(SDS_STATE *ss) {
  struct passwd *pw = NULL;
  struct group *gr = NULL;

  if (geteuid() != 0) {
    warnx("uid != 0. Not dropping privs");
    return 1;
  }

  SETVAR(ss->proc.user, SDS_USER);
  SETVAR(ss->proc.group, SDS_GROUP);
  SETVAR(ss->proc.chroot, SDS_CHROOT);

  if ((pw = getpwnam(ss->proc.user)) == NULL) {
    warnx("user does not exist: %s", ss->proc.user);
    return -1;
  }

  if ((gr = getgrnam(ss->proc.group)) == NULL) {
    warnx("group does not exist: %s", ss->proc.group);
    return -1;
  }

  if (chroot(ss->proc.chroot) < 0) {
    warn("%s", ss->proc.chroot);
    return -1;
  }

  IS_ERR(chdir("/"));
  LTZERO(setgid(gr->gr_gid));
  LTZERO(setuid(pw->pw_uid));

  return 0;
}
