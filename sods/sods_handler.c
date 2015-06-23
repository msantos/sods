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

/*
 * <0: error
 *  0: no data
 * >0: data to send
 *
 */

/* FIXME As an optimization, the A response should
 * FIXME be sent out before the data is written
 * FIXME to the proxied socket.
 *
 */

    int
sds_handler(SDS_STATE *ss, SDS_PKT *pkt)
{
    ssize_t n = 0;

    LTZERO(ss->decapsulate(ss, pkt));   /* Parse data from application layer */
    n = pkt->forward(ss, pkt);          /* Write the data to the appropriate socket */
    if (n >= 0)
        (void)pkt->encode(ss, pkt);     /* Application encoding */

    (void)pkt->encapsulate(ss, pkt);    /* Encode packet into protocol format */

    return n;
}

    int
sds_decapsulate(SDS_STATE *ss, SDS_PKT *pkt)
{
    int type = 0;

    /* defaults */
    pkt->nread = BUFLEN;
    pkt->parse = &sds_dns_query_TXT;
    pkt->forward = &sds_io_read;
    pkt->encapsulate = &sds_dns_response;
    pkt->chksum = &sds_chk_isequal;

    switch ( (type = sds_dns_type(pkt))) {
        case ns_t_invalid:
            VERBOSE(0, "Invalid DNS packet");
            return -1;
        case ns_t_a:
            pkt->parse = &sds_dns_query_A;
            pkt->forward = &sds_io_write;
            pkt->encode = &sds_dns_enc_A;
            pkt->chksum = &sds_chk_notequal;
            break;
        case ns_t_txt:
            pkt->nread = BUFLEN * 2;    /* Up to 2 TXT records */
            pkt->encode = &sds_dns_enc_TXT;
            break;
        case ns_t_cname:
            pkt->encode = &sds_dns_enc_CNAME;
            break;
        case ns_t_null:
            pkt->nread = BUFLEN * 2;
            pkt->encode = &sds_dns_enc_NULL;
            break;
        case ns_t_ns:
        default:
            VERBOSE(0, "Unsupported packet type = %d\n", type);
            return -1;
    }

    LTZERO(sds_dns_getdn(ss, pkt));

    VERBOSE(2, "\t%s\n", pkt->buf);

    LTZERO(pkt->parse(ss, pkt));

    VERBOSE(1, "\t\tid = %d: up = %u, down = %u\n", pkt->sess.f.id,
            (u_int32_t)pkt->sum_up, (u_int32_t)pkt->sum);

    return 0;
}

    int
sds_chk_notequal(SDS_STATE *ss, int a, int b)
{
    VERBOSE(1, "sum: saved = %d, packet = %d\n", a, b);

    /* New connections */
    if ((a == 0) && (b == 0))
        return 0;

    if (a != b)
        return 0;

    VERBOSE(0, "Duplicate packet, discarding: sum = %d\n", a);
    return -1;
}

    int
sds_chk_isequal(SDS_STATE *ss, int a, int b)
{
    if (a == b)
        return 0;

    VERBOSE(0, "Re-transmitting buffer: saved = %d, sent = %d\n",
            a, b);

    return -1;
}
