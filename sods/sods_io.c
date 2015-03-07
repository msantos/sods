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
#include "sods.h"
#include "sods_io.h"

SDS_FWD * sds_io_forward(SDS_STATE *ss, SDS_PKT *pkt);

    int
sds_io_write(SDS_STATE *ss, SDS_PKT *pkt)
{
    SDS_CONN *sc = NULL;
    ssize_t n = 0;
    ssize_t t = 0;

#ifdef HAVE_SEND
    int flags = MSG_NOSIGNAL;
#else
    int flags = 0;
#endif

    if ( (sc = sds_q_get(pkt->sess.f.id)) == NULL) {
        if ( (sc = sds_io_open(ss, pkt)) == NULL) {
            pkt->err = ns_r_servfail;
            return (-1);
        }
    }

    if (pkt->chksum(ss, sc->sum_up, pkt->sum_up) < 0)
        return (0);

    while ( (n = send(sc->s, pkt->buf + t, pkt->buflen - t, flags)) != (pkt->buflen - t)) {
        if (n == -1) {
            (void)sds_q_del(sc->id);
            warn("socket send");
            return (n);
        }
        t += n;
    }
    sc->sum_up = pkt->sum_up;
    sc->lastseen = time(NULL);

    return (pkt->buflen);
}

    int
sds_io_read(SDS_STATE *ss, SDS_PKT *pkt)
{
    SDS_CONN *sc = NULL;
    ssize_t n = 0;

    if ( (sc = sds_q_get(pkt->sess.f.id)) == NULL) {
        if ( (sc = sds_io_open(ss, pkt)) == NULL) {
            pkt->err = ns_r_servfail;
            return (-1);
        }
    }

    if (pkt->chksum(ss, sc->sum, pkt->sum) < 0) {
        (void)memcpy(pkt->buf, sc->buf, sc->buflen);
        pkt->buflen = sc->buflen;
        return (pkt->buflen);
    }

    sc->lastseen = time(NULL);

    errno = 0;
    n = read(sc->s, pkt->buf, pkt->nread);

    switch (n) {
        case -1:
            switch (errno) {
                case EAGAIN:
                    n = 0;
                    break;
                default:
                    (void)sds_q_del(sc->id);
                    warn("socket read");
                    break;
            }
            break;
        case 0:
            sds_io_close(sc);
            (void)sds_q_del(sc->id);
            break;
        default:
            sc->buflen = pkt->buflen = n;
            pkt->sum += n;
            sc->sum = pkt->sum;
            (void)memcpy(sc->buf, pkt->buf, pkt->buflen);
            break;
    }

    return (n);
}

    SDS_CONN *
sds_io_open(SDS_STATE *ss, SDS_PKT *pkt)
{
    SDS_CONN *sc = NULL;
    SDS_FWD *fw = NULL;
    int flags = 0;
#ifdef HAVE_SETSOCKOPT
    int onoff = 1;
#endif /* HAVE_SETSOCKOPT */
    char src[INET_ADDRSTRLEN] = {0};
    char dst[INET_ADDRSTRLEN] = {0};

    if ( (sc = sds_io_alloc(ss, pkt)) == NULL)
        return (NULL);

    fw = sds_io_forward(ss, pkt);

    sc->sa.sin_family = AF_INET;
    sc->sa.sin_port = fw->sa.sin_port;
    sc->sa.sin_addr.s_addr = fw->sa.sin_addr.s_addr;

    VERBOSE(0, "Connecting id = %u, %s:%d -> %s:%d\n", pkt->sess.f.id,
            inet_ntop(AF_INET, &pkt->sa.sin_addr, src, sizeof(src)),
            htons(pkt->sa.sin_port),
            inet_ntop(AF_INET, &sc->sa.sin_addr, dst, sizeof(dst)),
            htons(sc->sa.sin_port));

    if ( (sc->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        err(EXIT_FAILURE, "socket");

    flags = fcntl(sc->s, F_GETFL, 0);
    flags |= O_NONBLOCK;
    (void)fcntl(sc->s, F_SETFL, flags);

#ifdef HAVE_SETSOCKOPT
    IS_ERR(setsockopt(sc->s, SOL_SOCKET, SO_NOSIGPIPE, &onoff, sizeof(onoff)));
#endif /* HAVE_SETSOCKOPT */

    errno = 0;
    if (connect(sc->s, (const struct sockaddr *)&sc->sa, sizeof(sc->sa)) < 0) {
        switch (errno) {
            case EINPROGRESS:
                break;
            case EAGAIN:
                VERBOSE(0, "no ports available");
                pkt->err = ns_r_servfail;
                sds_io_close(sc);
                (void)sds_q_del(sc->id);
                return (NULL);
                break;
            default:
                err(EXIT_FAILURE, "connect");
        }
    }
    return (sc);
}

    int
sds_io_close(void *qe)
{
    SDS_CONN *sc = (SDS_CONN *)qe;
    return (close(sc->s));
}

    SDS_CONN *
sds_io_alloc(SDS_STATE *ss, SDS_PKT *pkt)
{
    SDS_CONN *sc = NULL;

    if (sds_q_init() < 0)
        errx(1, "sds_q_init");

    IS_NULL(sc = calloc(1, sizeof(SDS_CONN)));

    sc->id = pkt->sess.f.id;
    sc->lastseen = time(NULL);
    sc->close = &sds_io_close;

    if (sds_q_add(ss, sc) < 0) {
        free (sc);
        return (NULL);
    }

    return (sc);
}

    SDS_FWD *
sds_io_forward(SDS_STATE *ss, SDS_PKT *pkt)
{
    return ( (pkt->sess.f.fwd < ss->fwds) ?
            (ss->fwd + pkt->sess.f.fwd) :
            ss->fwd);
}
