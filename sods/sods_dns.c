/* Copyright (c) 2009-2016, Michael Santos <michael.santos@gmail.com>
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
#include "sods_dns.h"
#include <resolv.h>

#define NULL_RESPONSE(x) do { \
        if ((x)->buflen == 0) { \
            (void)memset(&(x)->buf, 0, sizeof((x)->buf)); \
            (x)->buflen =  1; \
            return ((x)->buflen); \
        } \
} while (0)


/* Look for the end of the query, indicated by
 * a NULL. Copy the next 2 bytes and put into
 * host endian format.
 *
 * Definitely not as elegant as in dproxy :)
 *
 * XXX use dn_skipname()
 *
 */
    int
sds_dns_type(SDS_PKT *pkt)
{
    u_char *p = NULL;

    if ( (p = memchr(pkt->data.query, '\0', pkt->datalen - sizeof(pkt->data.hdr) - 1)) == NULL)
        return 0;

    (void)memcpy(&pkt->type, p + 1, sizeof(pkt->type));
    return (pkt->type = ntohs(pkt->type));
}

/*
 * Expand the domain name.
 */
    int
sds_dns_getdn(SDS_STATE *ss, SDS_PKT *pkt)
{
    u_char *p = NULL;

    /* Truncate the query, if a recursive DNS server has added
     * additional records.
     */
    if ( (pkt->data.hdr.no_additional > 0) ||
            (pkt->data.hdr.no_answers > 0) ||
            (pkt->data.hdr.no_authority > 0)) {

        VERBOSE(3, "Truncating query: no_additional = %d, no_answers = %d, no_authority = %d\n",
                htons(pkt->data.hdr.no_additional), htons(pkt->data.hdr.no_answers),
                htons(pkt->data.hdr.no_authority));

        if ( (p = memchr(pkt->data.query, '\0', pkt->datalen - sizeof(pkt->data.hdr) - 4)) == NULL)
            return -1;

        pkt->datalen = sizeof(pkt->data.hdr) + strlen((char *)pkt->data.query) + 5; /* 2 * sizeof(u_int16_t): NS type, NS class */

        pkt->data.hdr.no_additional = 0;
        pkt->data.hdr.no_answers = 0;
        pkt->data.hdr.no_authority = 0;
    }

    return dn_expand((const u_char *)&pkt->data.hdr,
                (const u_char *)&pkt->data.hdr + pkt->datalen,
                (const u_char *)&pkt->data.query, pkt->buf,
                sizeof(pkt->buf));
}

/*
 * DNS QUERIES
 */

/*
 * A records
 *
 * WRITE request
 *
 */
    int
sds_dns_query_A(SDS_STATE *ss, SDS_PKT *pkt)
{
    char *b32 = NULL;
    char *domain = NULL;
    char *p = NULL;
    char *q = NULL;

    int rv = -1;

    IS_NULL(b32 = strdup(pkt->buf));
    IS_NULL(domain = calloc(NS_MAXDNAME, 1));

    /*%s.%u-%u.id-%d.up.%s */
    /* parse out the base32 encoded data */
    if ( (p = strchr(b32, '-')) == NULL)
        goto ERR;
    *p++ = '\0';

    if (sscanf(p, "%u.id-%u.up.%32s", (u_int32_t *)&pkt->sum_up,
                &pkt->sess.id, domain) != 3)
        goto ERR;

    pkt->sess.id = ntohl(pkt->sess.id);

    if ( (p = strrchr(b32, '.')) == NULL)
        goto ERR;

    *p = '\0';

    if (sds_dns_checkdn(ss, domain) < 0)
        goto ERR;

    for (p = q = b32; *p; p++)
        if (*p != '.') *q++ = *p;
    *q = '\0';

    pkt->buflen = base32_decode_into(b32, sizeof(pkt->buf), pkt->buf);
    rv = 0;

ERR:
    free(b32);
    free(domain);
    return rv;
}

/*
 * TXT records
 *
 * READ request
 *
 */
    int
sds_dns_query_TXT(SDS_STATE *ss, SDS_PKT *pkt)
{
    u_int32_t nonce = 0;
    char domain[NS_MAXDNAME] = {0};

    if (sscanf(pkt->buf, "%u-%u.id-%u.down.%32s", (u_int32_t *)&pkt->sum,
                &nonce, &pkt->sess.id, domain) != 4)
        return -1;

    pkt->sess.id = ntohl(pkt->sess.id);

    return sds_dns_checkdn(ss, domain);
}


/*
 * DNS REPLIES
 */

/*
 * Set the flags for a response packet.
 *
 *  Zero header, except for opcode and
 *  recursion request.
 *
 * 7    9    0    0
 * 0111 1001 0000 0000
 * .111 1... .... .... opcode
 * .... ...1 .... .... recursion desired
 *
 *  Set response and authoritative bit.s
 *
 * 8    4    8    0
 * 1000 0000 0000 0000
 * 1... .... .... .... message is a response
 * .... .1.. .... .... authoritative server
 * .... .... 1... .... recursion available
 *
 * 0    0    0    5
 * 0000 0000 0000 0101 error: REFUSED
 *
 * 0    0    0    2
 * 0000 0000 0000 0101 error: SERVFAIL
 *
 */
    void
sds_dns_setflags(SDS_STATE *ss, SDS_PKT *pkt)
{
    pkt->data.hdr.flags &= htons(0x7900);
    pkt->data.hdr.flags |= htons(0x8480);

    if (pkt->err)
        pkt->data.hdr.flags |= htons(pkt->err);
}

/*
 * A response
 */
    ssize_t
sds_dns_enc_A(SDS_STATE *ss, SDS_PKT *pkt)
{
    (void)memcpy(&pkt->buf, &ss->ip.s_addr, NS_INADDRSZ);
    pkt->buflen = NS_INADDRSZ;
    ss->ip.s_addr = htonl(ntohl(ss->ip.s_addr)+1);
    return pkt->buflen;
}

/*
 * TXT response
 */
    ssize_t
sds_dns_enc_TXT(SDS_STATE *ss, SDS_PKT *pkt)
{
    char b64[NS_PACKETSZ] = {0};
    struct dns_txtrec txt;
    ssize_t len = 0;
    size_t t = 0;

    NULL_RESPONSE(pkt);

    for ( len = 0; len < pkt->buflen; len += BUFLEN) {
        ssize_t s = MIN(pkt->buflen - len, BUFLEN);

        (void)memset(&txt, 0, sizeof(struct dns_txtrec));
        if (b64_ntop((u_char *)pkt->buf+len, s, txt.data, sizeof(txt.data)) < 0)
            errx(EXIT_FAILURE, "sds_dns_enc_TXT: invalid input: %zu/%zu",
                    s, sizeof(txt.data));
        txt.len = BASE64_LENGTH(s);
        (void)memcpy(b64 + t, &txt, sizeof(txt.len) + txt.len);
        t += sizeof(txt.len) + txt.len;
    }

    (void)memset(&pkt->buf, 0, sizeof(pkt->buf));
    (void)memcpy(&pkt->buf, b64, t);
    pkt->buflen = t;
    return t;
}


/*
 * CNAME response
 */
    ssize_t
sds_dns_enc_CNAME(SDS_STATE *ss, SDS_PKT *pkt)
{
    char *buf = NULL;
    char *p = NULL;
    char *cp = NULL;
    int i = 0;
    int j = 0;
    int n = 0;

    NULL_RESPONSE(pkt);

    IS_NULL(buf = calloc(sizeof(pkt->buf), 1));

    n = base32_encode_length(pkt->buflen); /* len includes NULL */
    if (n < 0 || (size_t)(n + (n/NS_MAXLABEL + 1) + 1) >= sizeof(pkt->buf)) {
        VERBOSE(0, "buffer overflow, biatch!");
        free(buf);
        return -1;
    }

    base32_encode_into(pkt->buf, pkt->buflen, buf);

    (void)memset(pkt->buf, 0, sizeof(pkt->buf));

    cp = pkt->buf;
    p = buf;

    /* Compressed name:
     *
     *  www.google.com
     *  CNAME: www.l.google.com
     *  <len><data><len><data><pointer>
     *  03 77 77 77 01 6c c0 10
     *
     * If there is no pointer, the domain
     * name is null terminated.
     *
     * www.apple.com
     * CNAME: www.apple.com.akadns.net
     *
     * 00 1a: length of data
     * 03 77 77 77 = www
     * 05 61 70 70 6c 65 = apple
     * 03 63 6f 6d = com
     * 06 61 6b 61 64 6e 73 = akadns
     * 03 6e 65 74 = net
     * 00 = terminating NULL
     *
     * NS_MAXLABEL includes the length
     * byte.
     *
     */
    //n = strlen(buf);
    n--; /* Remove terminating NULL */
    for (i = 0; i < n - 1; i += NS_MAXLABEL - 1) {
        ssize_t s = MIN(n - i, NS_MAXLABEL - 1);

        *cp++ = s;
        (void)memcpy(cp, p, s);
        p += s;
        cp += s;
        j++;
    }

    free (buf);

    /* b32 length + # length fields + terminating NULL */
    pkt->buflen = n + j + 1;
    return pkt->buflen;
}

/*
 * NULL response
 *
 */
    ssize_t
sds_dns_enc_NULL(SDS_STATE *ss, SDS_PKT *pkt)
{
    char b64[NS_PACKETSZ] = {0};
    size_t len = 0;

    NULL_RESPONSE(pkt);

    len = BASE64_LENGTH(pkt->buflen);
    if (b64_ntop((u_char *)pkt->buf, pkt->buflen, b64, sizeof(b64)) < 0)
        errx(EXIT_FAILURE, "sds_dns_enc_NULL: invalid input: %zu/%zu",
                len, sizeof(b64));

    (void)memset(&pkt->buf, 0, sizeof(pkt->buf));
    (void)memcpy(&pkt->buf, b64, len);
    pkt->buflen = len;
    return pkt->buflen;
}


/*
 * Generic DNS repsonse for READ requests
 */
    int
sds_dns_response(SDS_STATE *ss, SDS_PKT *pkt)
{
    struct dns_answer ans;

    (void)memset(&ans, 0, sizeof(ans));
    sds_dns_setflags(ss, pkt);

    pkt->data.hdr.no_answers = htons(1);

    ans.name = htons(0xc00c);
    ans.type = htons(pkt->type);
    ans.class = htons(ns_c_in);
    ans.ttl = 0;
    ans.data_len = htons(pkt->buflen);

    sds_dns_packet(pkt, &ans, sizeof(ans));
    sds_dns_packet(pkt, &pkt->buf, pkt->buflen);

    (void)memcpy(&pkt->buf, &pkt->data, sizeof(pkt->buf)); /* XXX */
    pkt->buflen = pkt->datalen;

    return 0;
}


    void
sds_dns_packet(SDS_PKT *pkt, void *data, size_t len)
{
    if (pkt->datalen + len > NS_PACKETSZ) {
        warnx("Buffer overflow!!!");
        return;
    }

    (void)memcpy((char *)&pkt->data + pkt->datalen, data, len);
    pkt->datalen += len;
}

    int
sds_dns_checkdn(SDS_STATE *ss, char *domain)
{
    char *p = NULL;
    int i = 0;

    p = strchr(domain, '.');
    *p++ = '\0';

#if 0
    if (strcmp(domain, "sshdns") != 0)
        return -1;
#endif

    if (strcmp(ss->dn[0], "any") == 0)
        return 0;

    for ( i = 0; i < ss->dn_max; i++) {
        if (strncmp(ss->dn[i], p, strlen(ss->dn[i])+1) == 0)
            return 0;
    }

    VERBOSE(1, "rejecting request for domain: %s\n", p);
    return -1;
}
