/*
 * Socket over DNS server.
 *
 * Copyright (c) 2009-2013 Michael Santos <michael.santos@gmail.com>
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
#include <unistd.h>
#include <fcntl.h>

SDS_CONN * sds_io_open(SDS_STATE *ss, SDS_PKT *pkt);
SDS_CONN * sds_io_alloc(SDS_STATE *ss, SDS_PKT *pkt);
