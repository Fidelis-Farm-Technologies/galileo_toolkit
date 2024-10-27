/*
 * Galileo Network Analytics (GNA) Toolkit
 * 
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

#define _GNU_SOURCE
#pragma once

#include <stdlib.h>
#include <stdint.h>

#include <yaf/decode.h>
#include <yaf/yafcore.h>
#include <fixbuf/public.h>

#include <airframe/mio.h>
#include <airframe/mio_config.h>
#include <airframe/mio_sink_file.h>
#include <airframe/airutil.h>
#include <airframe/daeconfig.h>

#include <ndpi/ndpi_api.h>
#include <duckdb.h>
#include <maxminddb.h>

#define ASNORG_LEN 32


#define FLOW_SCHEMA                                                                        \
    "CREATE TABLE flow ("                                                                  \
    "observ VARCHAR,stime TIMESTAMP,etime TIMESTAMP,dur UINTEGER,rtt UINTEGER, pcr FLOAT," \
    "proto VARCHAR,addr VARCHAR,raddr VARCHAR,port USMALLINT,rport USMALLINT,"             \
    "iflags VARCHAR,uflags VARCHAR,"                                                       \
    "tcpseq UINTEGER,rtcpseq UINTEGER,"                                                    \
    "vlan USMALLINT,rvlan USMALLINT,"                                                      \
    "pkts UBIGINT,rpkts UBIGINT,"                                                          \
    "bytes UBIGINT,rbytes UBIGINT,"                                                        \
    "entropy UTINYINT,rentropy UTINYINT,"                                                  \
    "iat UBIGINT,riat UBIGINT,"                                                            \
    "stdev UBIGINT,rstdev UBIGINT,"                                                        \
    "tcpurg UINTEGER,rtcpurg UINTEGER,"                                                    \
    "smallpktcnt UINTEGER,rsmallpktcnt UINTEGER,"                                          \
    "largpktcnt UINTEGER,rlargpktcnt UINTEGER,"                                            \
    "nonemptypktcnt UINTEGER,rnonemptypktcnt UINTEGER,"                                    \
    "firstnonemptycnt USMALLINT,rfirstnonemptycnt USMALLINT,"                              \
    "stdevpayload USMALLINT,rstdevpayload USMALLINT,"                                      \
    "maxpktsize USMALLINT,rmaxpktsize USMALLINT,"                                          \
    "spd VARCHAR,appid VARCHAR,reason VARCHAR,"                                            \
    "mac VARCHAR,rmac VARCHAR,"                                                            \
    "country VARCHAR,rcountry VARCHAR,"                                                    \
    "asn UINTEGER,rasn UINTEGER,"                                                          \
    "asnorg VARCHAR,rasnorg VARCHAR,"                                                      \
    "model VARCHAR,score FLOAT"                                                            \
    ")"

gboolean
OpenFileSink(
    MIOSource *source,
    MIOSink *sink,
    void *vctx,
    uint32_t *flags,
    GError **err);

gboolean
CloseFileSink(
    MIOSource *source,
    MIOSink *sink,
    void *vctx,
    uint32_t *flags,
    GError **err);

gboolean
ReaderToFileSink(
    MIOSource *source,
    MIOSink *sink,
    void *ctx,
    uint32_t *flags,
    GError **err);

gboolean
SocketToFileSink(
    MIOSource *source,
    MIOSink *sink,
    void *vctx,
    uint32_t *flags,
    GError **err);

