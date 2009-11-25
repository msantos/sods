/*
 * Socket over DNS server.
 *
 * Copyright (c) 2008 Michael Santos <michael.santos@gmail.com>
 *
 */

#include <pwd.h>
#include <grp.h>

#include "sods.h"

#define SDS_USER    "nobody"
#define SDS_GROUP   "nogroup"

#define SDS_CHROOT  "/var/chroot/sods"

#define SETVAR(x, y)    ((x) = ((x) == NULL) ? (y) : (x))


void sds_priv_daemon(SDS_STATE *ss);
int sds_priv_drop(SDS_STATE *ss);

extern char *__progname;

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
    openlog(__progname, LOG_NDELAY, LOG_DAEMON);
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

