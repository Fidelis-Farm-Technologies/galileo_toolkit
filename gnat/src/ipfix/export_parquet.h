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
    "proto VARCHAR,saddr VARCHAR,daddr VARCHAR,sport USMALLINT,dport USMALLINT,"           \
    "iflags VARCHAR,uflags VARCHAR,"                                                       \
    "stcpseq UINTEGER,dtcpseq UINTEGER,"                                                   \
    "svlan USMALLINT,dvlan USMALLINT,"                                                     \
    "spkts UBIGINT,dpkts UBIGINT,"                                                         \
    "sbytes UBIGINT,dbytes UBIGINT,"                                                       \
    "sentropy UTINYINT,dentropy UTINYINT,"                                                 \
    "siat UBIGINT,diat UBIGINT,"                                                           \
    "sstdev UBIGINT,dstdev UBIGINT,"                                                       \
    "stcpurg UINTEGER,dtcpurg UINTEGER,"                                                   \
    "ssmallpktcnt UINTEGER,dsmallpktcnt UINTEGER,"                                         \
    "slargpktcnt UINTEGER,dlargpktcnt UINTEGER,"                                           \
    "snonemptypktcnt UINTEGER,dnonemptypktcnt UINTEGER,"                                   \
    "sfirstnonemptycnt USMALLINT,dfirstnonemptycnt USMALLINT,"                             \
    "sstdevpayload USMALLINT,dstdevpayload USMALLINT,"                                     \
    "smaxpktsize USMALLINT,dmaxpktsize USMALLINT,"                                         \
    "spd VARCHAR,appid VARCHAR,reason VARCHAR,"                                            \
    "smac VARCHAR,dmac VARCHAR,"                                                           \
    "scountry VARCHAR,dcountry VARCHAR,"                                                   \
    "sasn UINTEGER,dasn UINTEGER,"                                                         \
    "sasnorg VARCHAR,dasnorg VARCHAR,"                                                     \
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

