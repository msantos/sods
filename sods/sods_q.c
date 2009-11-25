/*
 * Socket over DNS server.
 *
 * Copyright (c) 2008 Michael Santos <michael.santos@gmail.com>
 *
 */

#include "sods.h"
#include "sods_q.h"

LIST_HEAD(listhead, _SDS_CONN) head;
struct listhead *headp;

int init = 0;
int nel = 0;

    int
sds_q_init(void)
{
    if (init == 0) {
        LIST_INIT(&head);
        init = 1;
    }
    return (0);
}

    SDS_CONN *
sds_q_get(u_int32_t id)
{
    SDS_CONN *qe = NULL;

    if (&head == NULL)
        return (NULL);

    LIST_FOREACH(qe, &head, entries)
    {
        if (qe->id == id)
            return (qe);
    }

    return (NULL);
}

    int
sds_q_add(SDS_STATE *ss, SDS_CONN *sc)
{
    if (nel >= ss->maxconn) {
        if (sds_q_free(ss) == 0)
            return (-1); /* No slots available */
    }

    LIST_INSERT_HEAD(&head, sc, entries);
    nel++;

    return (0);
}

    int
sds_q_del(u_int32_t id)
{
    SDS_CONN *qe = NULL;

    LIST_FOREACH(qe, &head, entries)
    {
        if (qe->id == id) {
            qe->close(qe);
            LIST_REMOVE(qe, entries);
            free(qe);
            nel--;
            return (0);
        }
    }
    return (-1);
}

    int
sds_q_free(SDS_STATE *ss)
{
    SDS_CONN *qe = NULL;
    time_t now = 0;
    int rv = 0;

    now = time(NULL);

    LIST_FOREACH(qe, &head, entries)
    {
        if (now - qe->lastseen >= ss->maxtimeout) {
            qe->close(qe);
            LIST_REMOVE(qe, entries);
            free(qe);
            rv++;
            nel--;
        }
    }

    return (rv);
}

    void
sds_q_destroy(void)
{
    while (head.lh_first != NULL)
        LIST_REMOVE(head.lh_first, entries);
}

    void
sds_cleanup (void *state)
{
    SDS_STATE *ss = (SDS_STATE *)state;
    int n = 0;

    VERBOSE(3, "cleaning up connections\n");

    if ( (init == 0) || nel == 0)
        return;

    n = sds_q_free(ss);

    if (n > 0)
        VERBOSE(0, "freed client connections = %d\n", n);
}
