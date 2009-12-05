/*
 * Socket over DNS client.
 *
 * Copyright (c) 2009 Michael Santos <michael.santos@gmail.com>
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
#include <time.h>

#include <arpa/nameser.h>

#define SDT_VERSION     "0.7"

#ifdef HAVE_ERRX
#include <err.h>
#else
#define err     sdt_err
#define errx    sdt_errx
#define warn    sdt_warn
#define warnx   sdt_warnx
#endif /* HAVE_ERRX */

#ifndef HAVE_ARC4RANDOM
#ifdef HAVE_SSL
#define arc4random  sdt_rand
#else
#define arc4random  random
#endif /* HAVE_SSL */
#endif /* HAVE_ARC4RANDOM */


#define IS_ERR(x) do { \
    if ((x) == -1) { \
        err(EXIT_FAILURE, "%s", #x); \
    } \
} while (0)

#define IS_NULL(x) do { \
    if ((x) == NULL) { \
        err(EXIT_FAILURE, "%s", #x); \
    } \
} while (0)

#define TIMESTAMP() do { \
           char outstr[200]; \
           time_t t; \
           struct tm *tmp; \
 \
           t = time(NULL); \
           tmp = localtime(&t); \
           if (tmp == NULL) { \
               perror("localtime"); \
               exit(EXIT_FAILURE); \
           } \
 \
           if (strftime(outstr, sizeof(outstr), "%Y-%m-%d %H:%M:%S ", tmp) == 0) { \
               (void)fprintf(stderr, "strftime returned 0"); \
               exit(EXIT_FAILURE); \
           } \
 \
           (void)fprintf(stderr, "%s", outstr); \
} while (0)


#define VERBOSE(x, ...) do { \
    if (ss->verbose_lines == 0) { \
        break; \
    } \
    ss->verbose_lines--; \
    if (ss->verbose >= 4) { \
        TIMESTAMP(); \
    } \
    if (ss->verbose >= x) { \
        (void)fprintf (stderr, __VA_ARGS__); \
    } \
} while (0)

#define MAXBUF      47      /* MIME has a maximum line length of 76 bytes:
                               76 * 5 / 8 =  47 bytes */

#define SLEEP_TXT   20000   /* microseconds */
#define MAXBACKOFF  3000    /* 3000 * 20000  = 60,000,000 (1/minute) */
#define MAXPOLLFAIL  10      /* Number of TXT record failures before giving up */


typedef union _SDT_ID {
    struct {
        u_int32_t opt:8,
                  fwd:8,
                  id:16;
    } o;
    u_int32_t id;
} SDT_ID;

typedef struct _SDT_STATE {
    char        *dname;
    SDT_ID      sess;   
    size_t      sum;
    size_t      sum_up;
    size_t      bufsz;
    u_int16_t   backoff;
    u_int16_t   maxbackoff;
    u_int32_t   sleep;
    u_int32_t   type;
    int32_t     delay;
    int32_t   	faststart;
    int32_t   	pollfail;
    int32_t   	maxpollfail;
    pid_t       child;
    int         verbose;
    int         verbose_lines;
} SDT_STATE;

/* Resolver options */
enum {
    SDT_RES_RETRANS,        /* Resolver timeout */
    SDT_RES_RETRY,          /* Number of times to retry lookup */
    SDT_RES_USEVC,          /* Use TCP for lookup */
    SDT_RES_ROTATE,         /* Rotate through available nameservers */
    SDT_RES_BLAST,          /* Query all nameservers */
    SDT_RES_DEBUG,          /* Enable resolver debugging */
};

void sdt_loop_poll(SDT_STATE *ss);
void sdt_loop_A(SDT_STATE *ss);
void sdt_send_poll(SDT_STATE *ss);
void sdt_send_A(SDT_STATE *ss, char *buf, ssize_t n);
ssize_t sdt_read(SDT_STATE *ss, int fd, char *buf, size_t nbytes);
void sdt_alarm(SDT_STATE *ss);

int sdt_dns_init(void);
void sdt_dns_setopt(int opt, int val);
int sdt_dns_setns(char *ns);
int sdt_dns_parsens(SDT_STATE *ss, char *buf);
int sdt_dns_A(SDT_STATE *ss, char *buf, ssize_t n);
char *sdt_dns_poll(SDT_STATE *ss, size_t *len);
char *sdt_dns_parse(SDT_STATE *ss, char *pkt, int *pktlen);
char * sdt_dns_dec_CNAME(SDT_STATE *ss, u_char *data, u_int16_t *n);
char * sdt_dns_dec_TXT(SDT_STATE *ss, u_char *data, u_int16_t *n);
char * sdt_dns_dec_NULL(SDT_STATE *ss, u_char *data, u_int16_t *n);
void sdt_dns_print_servers(SDT_STATE *ss);

void sdt_rand_init(void);
#ifndef HAVE_ARC4RANDOM
u_int32_t sdt_rand(void);
#endif

void wakeup(int sig);
void usage(SDT_STATE *ss);

#ifndef HAVE_ERRX
void sdt_err(int rv, char *fmt, ...);
void sdt_errx(int rv, char *fmt, ...);
void sdt_warn(char *fmt, ...);
void sdt_warnx(char *fmt, ...);
#endif /* HAVE_ERRX */

