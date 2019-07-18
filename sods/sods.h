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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>

#include <netdb.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <sys/wait.h>

#include <sys/time.h>
#include <time.h>

#include <sys/queue.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <syslog.h>

#define SDS_VERSION "0.7.0"
#define SDS_PROGNAME "sods"

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifdef HAVE_ERRX
#include <err.h>
#else
#define err sds_err
#define errx sds_errx
#define warn sds_warn
#define warnx sds_warnx
#endif /* HAVE_ERRX */

#define IS_ERR(x)                                                              \
  do {                                                                         \
    if ((x) == -1) {                                                           \
      err(EXIT_FAILURE, "%s", #x);                                             \
    }                                                                          \
  } while (0)

#define LTZERO(x)                                                              \
  do {                                                                         \
    if ((x) < 0)                                                               \
      return (-1);                                                             \
  } while (0)

#define IS_NULL(x)                                                             \
  do {                                                                         \
    if ((x) == NULL) {                                                         \
      err(EXIT_FAILURE, "%s", #x);                                             \
    }                                                                          \
  } while (0)

#define VERBOSE(x, ...)                                                        \
  do {                                                                         \
    if (ss->verbose >= x) {                                                    \
      if (ss->daemon == 1)                                                     \
        syslog(LOG_INFO, __VA_ARGS__);                                         \
      else {                                                                   \
        sds_timestamp();                                                       \
        (void)fprintf(stderr, __VA_ARGS__);                                    \
      }                                                                        \
    }                                                                          \
  } while (0)

#define BUFLEN 110
#define NS_TXTREC                                                              \
  65535 /* see http://www.zeroconf.org/Rendezvous/txtrecords.html */

#define MAXFWDS 32       /* Maximum number of allowed forwarders */
#define MAXDNAMELIST 256 /* Maximum number of domain names */

struct SDS_PKT;
struct SDS_STATE;

typedef struct _SDS_FWD {
  u_int8_t sess; /* Unused */
  struct sockaddr_in sa;
} SDS_FWD;

typedef struct SDS_STATE {
  int s;
  char **dn;
  int dn_max;
  char *func; /* sshdns, socket ... */
  SDS_FWD *fwd;
  size_t fwds; /* number of forwarded sessions */
  struct {
    char *user;
    char *group;
    char *chroot;
  } proc;
  struct sockaddr_in local; /* local host */
  struct in_addr ip;        /* reported in DNS response */
  int maxconn;
  int maxtimeout;
  int daemon;
  int verbose;

  void (*run)(struct SDS_STATE *);
  void (*cleanup)(struct SDS_STATE *);
  int (*handler)(struct SDS_STATE *, struct SDS_PKT *);
  int (*decapsulate)(struct SDS_STATE *, struct SDS_PKT *);
} SDS_STATE;

struct dns_header {
  u_int16_t id;
  u_int16_t flags;
  u_int16_t no_questions;
  u_int16_t no_answers;
  u_int16_t no_authority;
  u_int16_t no_additional;
};

struct dns_answer {
  u_int16_t name;
  u_int16_t type;
  u_int16_t class;
  u_int16_t ttl;
  u_int16_t ttl2;
  u_int16_t data_len;
};

struct dns_txtrec {
  u_int8_t len;
  char data[256];
};

typedef union _SDS_ID {
  struct {
    u_int32_t opt : 8, fwd : 8, id : 16;
  } f;
  u_int32_t id;
} SDS_ID;

typedef struct SDS_PKT {
  struct {
    struct dns_header hdr;
    u_char query[NS_PACKETSZ - sizeof(struct dns_header)];
  } data;
  ssize_t datalen;
  u_int16_t type;        /* DNS message type */
  struct sockaddr_in sa; /* client source address */
  char buf[NS_PACKETSZ];
  ssize_t buflen;
  size_t sum_up;
  size_t sum;
  int err;
  SDS_ID sess;
  size_t nread; /* amount of data to read from socket */

  int (*parse)(SDS_STATE *, struct SDS_PKT *);
  ssize_t (*encode)(SDS_STATE *, struct SDS_PKT *);
  int (*encapsulate)(SDS_STATE *, struct SDS_PKT *);
  int (*chksum)(SDS_STATE *, int a, int b);
  int (*forward)(SDS_STATE *, struct SDS_PKT *);
} SDS_PKT;

struct _SDS_CONN {
  u_int32_t id;
  int s; /* socket */
  struct sockaddr_in sa;
  size_t sum;
  size_t sum_up;
  time_t lastseen;
  char buf[NS_PACKETSZ]; /* re-transmit buffer */
  size_t buflen;

  int (*close)(void *);
  LIST_ENTRY(_SDS_CONN) entries;
};

typedef struct _SDS_CONN SDS_CONN;

void sds_loop(SDS_STATE *ss);
void usage(SDS_STATE *ss);
void sds_timestamp(void);

/* queue */
int sds_q_init(void);
SDS_CONN *sds_q_get(u_int32_t id);
int sds_q_add(SDS_STATE *ss, SDS_CONN *sc);
int sds_q_del(u_int32_t id);
int sds_q_free(SDS_STATE *ss);
void sds_q_destroy(void);
void sds_cleanup(SDS_STATE *ss);

/* IO */
int sds_io_write(SDS_STATE *ss, SDS_PKT *pkt);
int sds_io_read(SDS_STATE *ss, SDS_PKT *pkt);
int sds_io_close(void *qe);

/* socket */
int sds_sock_init(SDS_STATE *ss);
void sds_sock_loop(SDS_STATE *ss);
int sds_sock_recv(SDS_STATE *ss, SDS_PKT *pkt);
int sds_sock_send(SDS_STATE *ss, SDS_PKT *pkt);

/* handler */
int sds_handler(SDS_STATE *ss, SDS_PKT *pkt);
int sds_decapsulate(SDS_STATE *ss, SDS_PKT *pkt);
int sds_chk_notequal(SDS_STATE *ss, int a, int b);
int sds_chk_isequal(SDS_STATE *ss, int a, int b);

/* DNS */
/* query */
int sds_dns_type(SDS_PKT *pkt);
int sds_dns_getdn(SDS_STATE *ss, SDS_PKT *pkt);
int sds_dns_query_A(SDS_STATE *ss, SDS_PKT *pkt);
int sds_dns_query_TXT(SDS_STATE *ss, SDS_PKT *pkt);
int sds_dns_checkdn(SDS_STATE *ss, char *domain);

/* response */
void sds_dns_setflags(SDS_STATE *ss, SDS_PKT *pkt);
ssize_t sds_dns_enc_A(SDS_STATE *ss, SDS_PKT *pkt);
ssize_t sds_dns_enc_TXT(SDS_STATE *ss, SDS_PKT *pkt);
ssize_t sds_dns_enc_CNAME(SDS_STATE *ss, SDS_PKT *pkt);
ssize_t sds_dns_enc_NULL(SDS_STATE *ss, SDS_PKT *pkt);
int sds_dns_response(SDS_STATE *ss, SDS_PKT *pkt);
void sds_dns_packet(SDS_PKT *pkt, void *data, size_t len);

int sds_priv_init(SDS_STATE *ss);

#ifndef HAVE_ERRX
void sds_err(int rv, char *fmt, ...);
void sds_errx(int rv, char *fmt, ...);
void sds_warn(char *fmt, ...);
void sds_warnx(char *fmt, ...);
#endif /* HAVE_ERRX */

#ifndef HAVE_STRTONUM
long long strtonum(const char *numstr, long long minval, long long maxval,
                   const char **errstrp);
#endif
