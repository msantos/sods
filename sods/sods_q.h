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
#ifndef LIST_FOREACH
#define LIST_FOREACH(var, head, field)                  \
        for((var) = (head)->lh_first; (var); (var) = (var)->field.le_next)
#endif /* LIST_FOREACH */

#ifndef LIST_FOREACH_SAFE
#define LIST_FIRST(head)        ((head)->lh_first)
#define LIST_END(head)          NULL
#define LIST_NEXT(elm, field)       ((elm)->field.le_next)

#define LIST_FOREACH_SAFE(var, head, field, tvar)           \
    for ((var) = LIST_FIRST(head);              \
        (var) && ((tvar) = LIST_NEXT(var, field), 1);       \
        (var) = (tvar))
#endif /* LIST_FOREACH_SAFE */
