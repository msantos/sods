/*
 * Scan IP ranges for DNS servers and for servers
 * supporting recursion.
 *
 * Copyright (c) 2008 Michael Santos <michael.santos@gmail.com>
 *
 */

/*
 * Parse an IP address and return a range.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int parseip (char *buf, in_addr_t *network, in_addr_t *broadcast);

