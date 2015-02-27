/*
 * Scan IP ranges for DNS servers and for servers
 * supporting recursion.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "ds.h"
#include "iprange.h"

#define DS_HOSTNAME    "www.example.com"

extern char *__progname;

typedef struct _DS_STATE {
    in_addr_t first;    /* host endian */
    in_addr_t last;    /* host endian */
    struct {
        in_port_t remote;
        in_port_t local;
    } port;
    int s;
    struct sockaddr_in sa;
    struct sockaddr_in lo;
    char *queryhost;
    int verbose;
} DS_STATE;

/* bit 0: message is a response
 * bit 7: recursion desired
 * bit 8: recursion available
 * bit 12, 13, 14, 15: reply code
 *      2 = SERVFAIL
 *      5 = REFUSED
 *
 *      1000 0000 1000 0001
 *      1... .... .... .... = response
 *      .000 0... .... .... = standard query
 *      .... ...0 .... .... = recursion not requested
 *      .... .... 1... .... = recursion available
 *      .... .... .... ...1 = authoritative answer not found
 *
 *      0001 0100 0000 1001
 *      0... .... .... .... = not a response
 *      .001 0... .... .... = ???
 *      .... ...0 .... .... = recursion not requested
 *      .... .... 0... .... = recursion not available
 *      .... .... .... 1001 = 9 ???
 *
 *      1000 0000 1000 0001
 *      1... .... .... .... = response
 *      .000 0... .... .... = ???
 *      .... ...0 .... .... = recursion not requested
 *      .... .... 1... .... = recursion available
 *      .... .... .... ...1 = not authoritative
 *
 *      0000 0000 1000 0001
 *      .... .... 1... .... = recursion available
 *      .... .... .... ...1 = not authoritative
 *
 *      1000 0001 0000 0000
 *      1... .... .... .... = response
 *      .000 0... .... .... = standard query
 *      .... ...1 .... .... = recursion requested
 *      .... .... 0... .... = recursion not available
 *      .... .... .... .... = no error
 */

struct dns_header {
    u_int16_t dns_id;
    u_int16_t dns_flags;
    u_int16_t dns_no_questions;
    u_int16_t dns_no_answers;
    u_int16_t dns_no_authority;
    u_int16_t dns_no_additional;
};

struct dns_answer {
    u_int16_t dns_name;
    u_int16_t dns_type;
    u_int16_t dns_class;
    u_int16_t dns_time_to_live;
    u_int16_t dns_time_to_live2;
    u_int16_t dns_data_len;
};


void ds_reader(DS_STATE *ds);
void ds_writer(DS_STATE *ds);
void wakeup(int sig);
void usage(DS_STATE *ds);

int woken = 0;

    int
main (int argc, char *argv[])
{
    DS_STATE *ds = NULL;
    pid_t pid = 0;

    int ch = 0;

    IS_NULL(ds = calloc(1, sizeof(DS_STATE)));

    ds->queryhost = DS_HOSTNAME;
    ds->port.remote = 53;
    ds->port.local = 53535;

    while ( (ch = getopt(argc, argv, "H:hl:p:v")) != -1) {
        switch (ch) {
            case 'H':
                ds->queryhost = optarg;
                break;
            case 'l':
                ds->port.local = (in_port_t)atoi(optarg);
                break;
            case 'p':
                ds->port.remote = (in_port_t)atoi(optarg);
                break;
            case 'v':
                ds->verbose++;
                break;
            case 'h':
            default:
                usage(ds);
        }
    }

    argc -= optind;
    argv += optind;

    if (argc != 1)
        usage(ds);

    if (parseip(argv[0], &ds->first, &ds->last) < 0)
        errx(EXIT_FAILURE, "Invalid address: %s", argv[0]);

    if (ds->last - ds->first > 2) {
        ds->last--;
        ds->first++;
    }

    if ( (ds->s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        err(EXIT_FAILURE, "socket");

    (void)memset(&ds->sa, 0, sizeof(struct sockaddr_in));
    ds->sa.sin_family = AF_INET;
    ds->sa.sin_port = htons(ds->port.remote);

    (void)memset(&ds->lo, 0, sizeof(struct sockaddr_in));
    ds->lo.sin_family = AF_INET;
    ds->lo.sin_addr.s_addr = INADDR_ANY;
    ds->lo.sin_port = htons(ds->port.local);

    IS_ERR(bind(ds->s, (struct sockaddr *)&ds->lo, sizeof(ds->lo)));

    switch ( (pid = fork())) {
        case -1:
            err(EXIT_FAILURE, "fork");
        case 0: /* child */
            ds_reader(ds);
            break;
        default:
            (void)signal(SIGCHLD, wakeup);
            ds_writer(ds);
            sleep (5);
            (void)kill(SIGTERM, pid);
            wait(NULL);
            break;
    }

    exit (EXIT_SUCCESS);
}

    void
ds_writer(DS_STATE *ds)
{
    u_char buf[NS_PACKETSZ] = {0};
    in_addr_t ip = 0;

    struct in_addr ia;

    if (res_mkquery(ns_o_query, DS_HOSTNAME, ns_c_in, ns_t_a, NULL, 0, NULL, buf, NS_PACKETSZ) < 0)
        errx(EXIT_FAILURE, "%s", hstrerror(h_errno));

    for (ip = ds->first; ip <= ds->last; ip++) {
        if (ds->verbose > 1) {
            ia.s_addr = ntohl(ip);
            (void)fprintf(stderr, "Sending: %s\n", inet_ntoa(ia));
        }

        ds->sa.sin_addr.s_addr = htonl(ip);
        if (sendto(ds->s, buf, NS_PACKETSZ, 0, (struct sockaddr *)&ds->sa, sizeof(ds->sa)) < 0)
            err(EXIT_FAILURE, "sendto");
    }
}

    void
ds_reader(DS_STATE *ds)
{
    u_char buf[NS_PACKETSZ] = {0};
    socklen_t len = 0;

    struct sockaddr_in sa;
    struct dns_header hdr;
    char *status = NULL;
    char *rerr = NULL;

    for ( ; ; ) {
        if (woken > 0) return;

        len = sizeof(sa);
        if (recvfrom(ds->s, buf, NS_PACKETSZ, 0, (struct sockaddr *)&sa, &len) < 0)
            warn("recvfrom");

        (void)memcpy(&hdr, buf, sizeof(hdr));

        hdr.dns_flags = ntohs(hdr.dns_flags);
        hdr.dns_id = ntohs(hdr.dns_id);

        /* 1000 0000 0000 0000 = 0x8000 (response) */
        /* 0000 0000 1000 0000 = 0x80 (recursion available) */
        if ( (hdr.dns_flags & 0x8000) == 0) {
            warnx("not a response packet: %s:%d = %u\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), hdr.dns_flags);
            continue;
        }

        rerr = "UNKNOWN";

        if (hdr.dns_flags & 0x80)
            status = "RECURSE";
        else {
            if (ds->verbose == 0)
                continue;
            status = "LOCALONLY";
        }

        if ( (hdr.dns_flags & 0x000F) == 0)
            rerr = "NOERR";
        else if (hdr.dns_flags & 0x0001)
            rerr = "NOT AUTHORITATIVE";
        else if (hdr.dns_flags & 0x0002)
            rerr = "SERVFAIL";
        else if (hdr.dns_flags & 0x0005)
            rerr = "REFUSED";

        if (ds->verbose > 0)
            (void)printf("Response: %s = %s/%s (%x) [%x]\n", inet_ntoa(sa.sin_addr),
                    status, rerr, hdr.dns_flags, hdr.dns_id);
        else
            (void)printf("%s = %s\n", inet_ntoa(sa.sin_addr), rerr);
    }
}

    void
wakeup (int sig)
{
    switch (sig) {
        case SIGCHLD:
            woken = 1;
            break;
        default:
            break;
    }
}

void
usage(DS_STATE *ds)
{
    (void)fprintf(stderr, "%s: <options> <ipaddr>\n\n", __progname);
    (void)fprintf(stderr,
            "-H <hostname>          Name used in query (default: " DS_HOSTNAME ")\n"
            "-h                     Usage\n"
            "-p <port>              Remote port (default: 53)\n"
            "-l <port>              Local port (default: 53535)\n"
            "-v                     Be more verbose\n"
            "\nExamples:\n"
            "ds -vv 8.8.8.8\n"
            "ds -v 8.8.4.4/24\n\n"
            "Use ctl-C to exit\n\n"
            );
    exit (EXIT_FAILURE);
}
