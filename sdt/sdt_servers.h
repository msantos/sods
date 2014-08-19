/*
 * Socket over DNS client.
 *
 * Copyright (c) 2009-2014 Michael Santos <michael.santos@gmail.com>
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

/* Publicly available recursive servers */
typedef struct _SDT_SERV  {
    char *name;
    char *descr;
    char *addr;
} SDS_SERV;

static SDS_SERV dnsserv[] = {
    {"opendns", "resolver1.opendns.com", "208.67.222.222"},
    {"opendns", "resolver2.opendns.com", "208.67.222.220"},

    {"verizon", "vnsc-bak.sys.gtei.net", "4.2.2.2"},
    {"verizon", "vnsc-lc.sys.gtei.net", "4.2.2.3"},
    {"verizon", "vnsc-pri-dsl.genuity.net", "4.2.2.4"},
    {"verizon", "vnsc-bak-dsl.genuity.net", "4.2.2.5"},
    {"verizon", "vnsc-lc-dsl.genuity.net", "4.2.2.6"},

    {"speakeasy", "Atlanta", "216.27.175.2"},
    {"speakeasy", "Boston", "66.92.64.2"},
    {"speakeasy", "Chicago", "64.81.159.2"},
    {"speakeasy", "Dallas", "64.81.127.2"},
    {"speakeasy", "Denver", "64.81.111.2"},
    {"speakeasy", "Los Angeles", "216.52.103.2"},
    {"speakeasy", "New York", "216.254.95.2"},
    {"speakeasy", "San Francisco", "64.81.79.2"},
    {"speakeasy", "Philadelphia", "66.92.224.2"},
    {"speakeasy", "Seattle", "216.231.41.22"},
    {"speakeasy", "Washington", "66.92.159.2"},
    {"speakeasy", "Secondary (tenerus)", "216.231.41.2"},

    {"google", "google-public-dns-a.google.com", "8.8.8.8"},
    {"google", "google-public-dns-b.google.com", "8.8.4.4"},

    {NULL, NULL, NULL}
};
