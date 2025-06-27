/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
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

#define FLOW_SCHEMA                                                                             \
    "CREATE TABLE flow ("                                                                       \
    "stream UINTEGER,id UUID,"                                                                  \
    "observe VARCHAR,stime TIMESTAMP,etime TIMESTAMP,dur UINTEGER,rtt UINTEGER,pcr INTEGER,"    \
    "proto VARCHAR,saddr VARCHAR,daddr VARCHAR,sport USMALLINT,dport USMALLINT,"                \
    "iflags VARCHAR,uflags VARCHAR,stcpseq UINTEGER,dtcpseq UINTEGER,"                          \
    "svlan USMALLINT,dvlan USMALLINT,spkts UBIGINT,dpkts UBIGINT,"                              \
    "sbytes UBIGINT,dbytes UBIGINT,sentropy UTINYINT,dentropy UTINYINT,"                        \
    "siat UBIGINT,diat UBIGINT,sstdev UBIGINT,dstdev UBIGINT,"                                  \
    "stcpurg UINTEGER,dtcpurg UINTEGER,ssmallpktcnt UINTEGER,dsmallpktcnt UINTEGER,"            \
    "slargepktcnt UINTEGER,dlargepktcnt UINTEGER,"                                              \
    "snonemptypktcnt UINTEGER,dnonemptypktcnt UINTEGER,"                                        \
    "sfirstnonemptycnt USMALLINT,dfirstnonemptycnt USMALLINT,"                                  \
    "smaxpktsize USMALLINT,dmaxpktsize USMALLINT,"                                              \
    "sstdevpayload USMALLINT,dstdevpayload USMALLINT,"                                          \
    "spd VARCHAR,reason VARCHAR,smac VARCHAR,dmac VARCHAR,"                                     \
    "scountry VARCHAR,dcountry VARCHAR,sasn UINTEGER,dasn UINTEGER,"                            \
    "sasnorg VARCHAR,dasnorg VARCHAR,orient VARCHAR,tag VARCHAR[],"                             \
    "hbos_score DOUBLE,hbos_severity UTINYINT,hbos_map MAP(VARCHAR, FLOAT),"                    \
    "ndpi_appid VARCHAR,ndpi_category VARCHAR,ndpi_risk_bits UBIGINT,ndpi_risk_score UINTEGER," \
    "ndpi_risk_severity UTINYINT, ndpi_risk_list VARCHAR[],trigger TINYINT);"

#define FLOW_GENERATE_UUID " UPDATE flow SET id = uuid()"


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
