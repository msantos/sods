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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/nameser.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <netdb.h>

#define SDT_VERSION "0.12.0"

#ifdef HAVE_ERRX
#include <err.h>
#else
#define err sdt_err
#define errx sdt_errx
#define warn sdt_warn
#define warnx sdt_warnx
#endif /* HAVE_ERRX */

#define IS_ERR(x)                                                              \
  do {                                                                         \
    if ((x) == -1) {                                                           \
      err(EXIT_FAILURE, "%s", #x);                                             \
    }                                                                          \
  } while (0)

#define IS_NULL(x)                                                             \
  do {                                                                         \
    if ((x) == NULL) {                                                         \
      err(EXIT_FAILURE, "%s", #x);                                             \
    }                                                                          \
  } while (0)

#define TIMESTAMP()                                                            \
  do {                                                                         \
    char _outstr[200];                                                         \
    time_t _t;                                                                 \
    struct tm *_tmp;                                                           \
                                                                               \
    _t = time(NULL);                                                           \
    _tmp = localtime(&_t);                                                     \
    if (_tmp == NULL) {                                                        \
      perror("localtime");                                                     \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
                                                                               \
    if (strftime(_outstr, sizeof(_outstr), "%Y-%m-%d %H:%M:%S ", _tmp) == 0) { \
      (void)fprintf(stderr, "strftime returned 0");                            \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
                                                                               \
    (void)fprintf(stderr, "%s", _outstr);                                      \
  } while (0)

#define VERBOSE(x, ...)                                                        \
  do {                                                                         \
    if (ss->verbose_lines == 0) {                                              \
      break;                                                                   \
    }                                                                          \
    ss->verbose_lines--;                                                       \
    if (ss->verbose >= 4) {                                                    \
      TIMESTAMP();                                                             \
    }                                                                          \
    if (ss->verbose >= x) {                                                    \
      (void)fprintf(stderr, __VA_ARGS__);                                      \
    }                                                                          \
  } while (0)

#define MAXBUF                                                                 \
  47 /* MIME has a maximum line length of 76 bytes:                            \
        76 * 5 / 8 =  47 bytes */

#define SLEEP_TXT 20000 /* microseconds */
#define MAXBACKOFF 3000 /* 3000 * 20000  = 60,000,000 (1/minute) */
#define MAXPOLLFAIL 10  /* Number of TXT record failures before giving up */

#define MAXDNAMELIST 256 /* arbitrary cutoff for number of domains */

typedef union _SDT_ID {
  struct {
    u_int32_t opt : 8, fwd : 8, id : 16;
  } o;
  u_int32_t id;
} SDT_ID;

typedef struct SDT_STATE {
  char **dname;
  int dname_max;
  int dname_iterator;
  SDT_ID sess;
  size_t sum;
  size_t sum_up;
  size_t bufsz;
  u_int16_t backoff;
  u_int16_t maxbackoff;
  u_int32_t sleep;
  u_int32_t type;
  int32_t delay;
  int32_t faststart;
  int32_t pollfail;
  int32_t maxpollfail;
  pid_t child;
  int verbose;
  int verbose_lines;
  int rand;

  in_port_t proxy_port;
  int fd_in;
  int fd_out;

  int protocol;
  char *target;
  in_port_t target_port;

  char *(*dname_next)(struct SDT_STATE *state);
} SDT_STATE;

/* Protocol version */
enum { PROTO_OZYMANDNS, PROTO_STATIC_FWD, PROTO_DYN_FWD };

/* Resolver options */
enum {
  SDT_RES_RETRANS, /* Resolver timeout */
  SDT_RES_RETRY,   /* Number of times to retry lookup */
  SDT_RES_USEVC,   /* Use TCP for lookup */
  SDT_RES_ROTATE,  /* Rotate through available nameservers */
  SDT_RES_BLAST,   /* Query all nameservers */
  SDT_RES_DEBUG,   /* Enable resolver debugging */
};

void sdt_parse_forward(SDT_STATE *ss, char *host);
int sdt_proxy_open(SDT_STATE *ss);
void sdt_loop_poll(SDT_STATE *ss);
void sdt_loop_A(SDT_STATE *ss);
void sdt_send_poll(SDT_STATE *ss);
void sdt_send_A(SDT_STATE *ss, char *buf, ssize_t n);
ssize_t sdt_read(SDT_STATE *ss, char *buf, size_t nbytes);
void sdt_alarm(SDT_STATE *ss);

int sdt_dns_init(void);
void sdt_dns_setopt(int opt, int val);
int sdt_dns_setns(char *ns);
int sdt_dns_parsens(SDT_STATE *ss, char *buf);
int sdt_dns_A(SDT_STATE *ss, char *buf, ssize_t n);
char *sdt_dns_poll(SDT_STATE *ss, ssize_t *len);
char *sdt_dns_parse(SDT_STATE *ss, char *pkt, int *pktlen);
char *sdt_dns_dec_CNAME(SDT_STATE *ss, u_char *data, u_int16_t *n);
char *sdt_dns_dec_TXT(SDT_STATE *ss, u_char *data, u_int16_t *n);
char *sdt_dns_dec_NULL(SDT_STATE *ss, u_char *data, u_int16_t *n);
void sdt_dns_print_servers(SDT_STATE *ss);
char *sdt_dns_dn_roundrobin(SDT_STATE *ss);
char *sdt_dns_dn_random(SDT_STATE *ss);

int sdt_rand_init(void);
u_int32_t sdt_arc4random(int);
#ifndef HAVE_ARC4RANDOM
u_int32_t sdt_rand(int);
#endif

void wakeup(int sig);
void usage(SDT_STATE *ss);

#ifndef HAVE_ERRX
void sdt_err(int rv, char *fmt, ...);
void sdt_errx(int rv, char *fmt, ...);
void sdt_warn(char *fmt, ...);
void sdt_warnx(char *fmt, ...);
#endif /* HAVE_ERRX */

#ifndef HAVE_STRTONUM
long long strtonum(const char *numstr, long long minval, long long maxval,
                   const char **errstrp);
#endif
