/*
 * Socket over DNS server.
 *
 * Copyright (c) 2008 Michael Santos <michael.santos@gmail.com>
 *
 */

#include <unistd.h>
#include <fcntl.h>

SDS_CONN * sds_io_open(SDS_STATE *ss, SDS_PKT *pkt);
SDS_CONN * sds_io_alloc(SDS_STATE *ss, SDS_PKT *pkt);

