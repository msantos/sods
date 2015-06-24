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

    return 0;
}

    void
sds_sock_loop(SDS_STATE *ss)
{
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
                return -1;
            default:
                err(EXIT_FAILURE, "sds_sock_recv: recvfrom");
        }
    }
    return 0;
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
                return -1;
            default:
                err(EXIT_FAILURE, "sds_sock_send: sendto");
        }
    }

    return 0;
}

void
sds_sighandler(int sig)
{
    docleanup = 1;
}
