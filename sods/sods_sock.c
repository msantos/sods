/*
 * Socket over DNS server.
 *
 * Copyright (c) 2009-2013 Michael Santos <michael.santos@gmail.com>
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
#include "sods.h"

void sds_sighandler (int sig);
int docleanup = 0;

    int
sds_sock_init(SDS_STATE *ss)
{
    struct sigaction sa;

    if ( (ss->s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        err(EXIT_FAILURE, "socket");

    IS_ERR(bind(ss->s, (struct sockaddr *)&ss->local, sizeof(ss->local)));

    if (sds_priv_init(ss) < 0)
        errx(EXIT_FAILURE, "Could not drop privs");

    sa.sa_handler = sds_sighandler;
    sigemptyset (&sa.sa_mask);
    sa.sa_flags = 0;

    (void)sigaction(SIGALRM, &sa, NULL);

    return (0);
}

    void
sds_sock_loop(void *vp)
{
    SDS_STATE *ss = (SDS_STATE *)vp;
    SDS_PKT *pkt = NULL;

    IS_NULL(pkt = calloc(1, sizeof(SDS_PKT)));

    (void)sds_sock_init(ss);

    for ( ; ; ) {
        (void)memset(pkt, 0, sizeof(SDS_PKT));

        if (docleanup == 1) {
            ss->cleanup(ss);
            docleanup = 0;
        }

        (void)alarm(ss->maxtimeout*2);
        if (sds_sock_recv(ss, pkt) < 0)
            continue;

        if (ss->handler(ss, pkt) < 0)
            continue;

        (void)sds_sock_send(ss, pkt); /* XXX need to re-send if failed */
    }
}

    int
sds_sock_recv(SDS_STATE *ss, SDS_PKT *pkt)
{
    socklen_t len = 0;

    len = sizeof(pkt->sa);
    errno = 0;
    if ( (pkt->datalen = recvfrom(ss->s, &pkt->data, sizeof(pkt->data), 0,
                (struct sockaddr *)&pkt->sa, &len)) < 0) {
        switch (errno) {
            case EAGAIN:
            case EINTR:
                return (-1);
            default:
                err(EXIT_FAILURE, "sds_sock_recv: recvfrom");
        }
    }
    return (0);
}

    int
sds_sock_send(SDS_STATE *ss, SDS_PKT *pkt)
{
    VERBOSE(2, "Sending: %s\n", inet_ntoa(pkt->sa.sin_addr));

    errno = 0;
    if (sendto(ss->s, pkt->buf, pkt->buflen, 0,
                (struct sockaddr *)&pkt->sa, sizeof(pkt->sa)) < 0) {
        switch (errno) {
            case EAGAIN:
            case EINTR:
                return (-1);
            default:
                err(EXIT_FAILURE, "sds_sock_send: sendto");
        }
    }

    return (0);
}

void
sds_sighandler(int sig)
{
    docleanup = 1;
}
