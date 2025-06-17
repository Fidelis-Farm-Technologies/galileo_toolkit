
#define _GNU_SOURCE
#pragma once

#include <math.h>
#include <fixbuf/public.h>
#include <ndpi/ndpi_api.h>
#include <duckdb.h>
#include <maxminddb.h>

typedef struct gnatContext_st
{
    uint32_t outtime;
    fBuf_t *input_buf;
    FILE *input_fp;
    fbConnSpec_t connection_spec;
    fbListener_t *listener;
    //
    fbInfoModel_t *model;
    fbTemplate_t *template;
    fbSession_t *session;
    fbCollector_t *collector;

    gboolean input_buf_ready;
    yfFlow_t flow;
    uint32_t rotate_interval;
    uint64_t ipfix_files;
    uint64_t ipfix_flows;
    uint64_t ipfix_flows_skipped;
    gboolean verbose;
    duckdb_database db;
    duckdb_connection con;
    duckdb_result result;
    duckdb_appender appender;
    struct ndpi_detection_module_struct *ndpi_ctx;
    MMDB_s asn_mmdb;
    MMDB_s *asn_mmdb_ptr;
    MMDB_s country_mmdb;
    MMDB_s *country_mmdb_ptr;
    char *input_file;
    char *observation;
    char *asn_file;
    char *country_file;
    char *output_dir;
    uint16_t risk_threshold;
} GNAT_CONTEXT;
