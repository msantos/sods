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
#include "sods_q.h"

LIST_HEAD(listhead, _SDS_CONN) head;
struct listhead *headp;

int init = 0;
int nel = 0;

int sds_q_init(void) {
  if (init == 0) {
    LIST_INIT(&head);
    init = 1;
  }
  return 0;
}

SDS_CONN *sds_q_get(u_int32_t id) {
  SDS_CONN *qe = NULL;

  LIST_FOREACH(qe, &head, entries) {
    if (qe->id == id)
      return qe;
  }

  return NULL;
}

int sds_q_add(SDS_STATE *ss, SDS_CONN *sc) {
  if (nel >= ss->maxconn) {
    if (sds_q_free(ss) == 0)
      return -1; /* No slots available */
  }

  LIST_INSERT_HEAD(&head, sc, entries);
  nel++;

  return 0;
}

int sds_q_del(u_int32_t id) {
  SDS_CONN *qe = NULL;
  SDS_CONN *qtmp = NULL;

  LIST_FOREACH_SAFE(qe, &head, entries, qtmp) {
    if (qe->id == id) {
      qe->close(qe);
      LIST_REMOVE(qe, entries);
      free(qe);
      nel--;
      return 0;
    }
  }
  return -1;
}

int sds_q_free(SDS_STATE *ss) {
  SDS_CONN *qe = NULL;
  SDS_CONN *qtmp = NULL;
  time_t now = 0;
  int rv = 0;

  now = time(NULL);

  LIST_FOREACH_SAFE(qe, &head, entries, qtmp) {
    if (now - qe->lastseen >= ss->maxtimeout) {
      qe->close(qe);
      LIST_REMOVE(qe, entries);
      free(qe);
      rv++;
      nel--;
    }
  }

  return rv;
}

void sds_q_destroy(void) {
  SDS_CONN *qe = NULL;

  while (!LIST_EMPTY(&head)) {
    qe = LIST_FIRST(&head);
    LIST_REMOVE(qe, entries);
    free(qe);
  }
}

void sds_cleanup(SDS_STATE *ss) {
  int n = 0;

  VERBOSE(3, "cleaning up connections\n");

  if ((init == 0) || nel == 0)
    return;

  n = sds_q_free(ss);

  if (n > 0)
    VERBOSE(0, "freed client connections = %d\n", n);
}
