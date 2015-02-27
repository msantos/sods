/*
 * Socket over DNS server.
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
#include <pwd.h>
#include <grp.h>

#include "sods.h"

#define SDS_USER    "nobody"
#define SDS_GROUP   "nogroup"

#define SDS_CHROOT  "/var/chroot/sods"

#define SETVAR(x, y)    ((x) = ((x) == NULL ? (y) : (x)))


void sds_priv_daemon(SDS_STATE *ss);
int sds_priv_drop(SDS_STATE *ss);


    int
sds_priv_init(SDS_STATE *ss)
{
    if (ss->daemon == 1)
        sds_priv_daemon(ss);
    return (sds_priv_drop(ss));
}

    void
sds_priv_daemon(SDS_STATE *ss)
{
    openlog(SDS_PROGNAME, LOG_NDELAY, LOG_DAEMON);
    IS_ERR(daemon(0, 0));
}

    int
sds_priv_drop(SDS_STATE *ss)
{
    struct passwd *pw = NULL;
    struct group *gr = NULL;

    if (geteuid() != 0) {
        warnx("uid != 0. Not dropping privs");
        return (1);
    }

    SETVAR(ss->proc.user, SDS_USER);
    SETVAR(ss->proc.group, SDS_GROUP);
    SETVAR(ss->proc.chroot, SDS_CHROOT);

    if ( (pw = getpwnam(ss->proc.user)) == NULL) {
        warnx("user does not exist: %s", ss->proc.user);
        return (-1);
    }

    if ( (gr = getgrnam(ss->proc.group)) == NULL) {
        warnx("group does not exist: %s", ss->proc.group);
        return (-1);
    }

    if (chroot(ss->proc.chroot) < 0) {
        warn("%s", ss->proc.chroot);
        return (-1);
    }

    IS_ERR(chdir("/"));
    LTZERO(setgid(gr->gr_gid));
    LTZERO(setuid(pw->pw_uid));

    return (0);
}
