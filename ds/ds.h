/*
 * Scan IP ranges for DNS servers and for servers
 * supporting recursion.
 *
 * Copyright (c) 2008 Michael Santos <michael.santos@gmail.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <signal.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/wait.h>

#define DS_VERSION     "0.01"

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
    if (ss->verbose >= 4) { \
        TIMESTAMP(); \
    } \
    if (ss->verbose >= x) { \
        (void)fprintf (stderr, __VA_ARGS__); \
    } \
} while (0)

