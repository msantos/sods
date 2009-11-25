/*
 * Socket over DNS server.
 *
 * Copyright (c) 2008 Michael Santos <michael.santos@gmail.com>
 *
 */

#ifndef LIST_FOREACH
#define LIST_FOREACH(var, head, field)                  \
        for((var) = (head)->lh_first; (var); (var) = (var)->field.le_next)
#endif /* LIST_FOREACH */
