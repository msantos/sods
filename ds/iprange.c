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

/*
 * Parse an IP address and return a range.
 */
#include "iprange.h"

in_addr_t quad2hl(char *buf);
in_addr_t mask2hl(char *buf);

    int
parseip (char *buf, in_addr_t *network, in_addr_t *broadcast)
{
    char *ip = NULL;
    char *mask = NULL;
    char *p = NULL;

    in_addr_t addr = 0;
    in_addr_t netmask = 0;

    if ( (ip = strdup(buf)) == NULL)
        err(EXIT_FAILURE, "strdup");

    p = strchr(ip, '/');
    if (p == NULL)
        mask = "32";
    else {
        *p++ = '\0';
        mask = p;
    }

    /* Determine the base IP address */
    if ( (addr = quad2hl(ip)) == 0) {
        warnx("Invalid IP address: %s", ip);
        goto ERR;
    }

    /* Get the mask */
    if ( (netmask = mask2hl(mask)) == 0)
        netmask = quad2hl(mask);

    if (netmask == 0) {
        warnx("Invalid netmask: %s", mask);
        goto ERR;
    }

    *network = addr & netmask;
    *broadcast = addr | ~netmask;

    free(ip);

    return (0);

ERR:
    free(ip);
    return -1;
}

    in_addr_t
quad2hl(char *buf)
{
    in_addr_t addr = 0;
    u_int32_t byte[4];
    int i = 0;

    if (buf == NULL)
        return (0);

    if (sscanf(buf, "%u.%u.%u.%u", &byte[0], &byte[1],
                &byte[2], &byte[3]) != 4)
        return (0);

    for (i = 0; i < 4; i++)
        if (byte[i] > 255)
            return (0);

    for (i = 0; i < 4; i++)
        addr += byte[i] << (24 - i * 8);

    return (addr);
}

    in_addr_t
mask2hl(char *buf)
{
    u_int32_t byte;
    in_addr_t mask = 0;

    if (buf == NULL)
        return (0);

    if (sscanf(buf, "%u", &byte) != 1)
        return (0);

    if (byte > 32 || byte == 0)
        return (0);

    while (byte > 0) {
        mask = (mask >> 1) + 0x80000000;
        byte--;
    }

    return (mask);
}
