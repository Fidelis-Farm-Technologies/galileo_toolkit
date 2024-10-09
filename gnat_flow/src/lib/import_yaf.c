/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

/*
 * YAF file processor using fixbuf library.
 * See: https://tools.netsa.cert.org/fixbuf/libfixbuf/
 */
#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <ndpi/ndpi_api.h>
#include <duckdb.h>
#include <maxminddb.h>

#include "import_yaf.h"

#define CSV_OUTPUT_VERSION 100
#define CSV_OUTPUT_VERSION_EXT 101
#define ASNORG_LEN 32

#define GLIB_ERROR_RETURN(e)                         \
    {                                                \
        fprintf(stderr, "%s:%d: %s\n",               \
                __FUNCTION__, __LINE__, e->message); \
        break;                                       \
    }

#if defined(ENABLE_PROCESS_STATS)
static int processYafStatsRecord(const FILE *output_fp, const YAF_STATS_RECORD *yaf_stats_record)
{
    return 0;
}
#endif


/* stats */
static uint32_t yac_files = 0;
static uint32_t yac_flows = 0;

static void
print_tcp_flags(
    GString *str,
    uint8_t flags,
    uint8_t rflags)
{

    if (flags & YF_TF_SYN)
    {
        g_string_append_c(str, 'S');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (rflags & YF_TF_SYN)
    {
        g_string_append_c(str, 's');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (flags & YF_TF_ACK)
    {
        g_string_append_c(str, 'A');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (rflags & YF_TF_ACK)
    {
        g_string_append_c(str, 'a');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (flags & YF_TF_RST)
    {
        g_string_append_c(str, 'R');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (rflags & YF_TF_RST)
    {
        g_string_append_c(str, 'r');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (flags & YF_TF_FIN)
    {
        g_string_append_c(str, 'F');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (rflags & YF_TF_FIN)
    {
        g_string_append_c(str, 'f');
    }
    else
    {
        g_string_append_c(str, '.');
    }

    if (flags & YF_TF_ECE)
    {
        g_string_append_c(str, 'E');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (rflags & YF_TF_ECE)
    {
        g_string_append_c(str, 'e');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (flags & YF_TF_CWR)
    {
        g_string_append_c(str, 'C');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (rflags & YF_TF_CWR)
    {
        g_string_append_c(str, 'c');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (flags & YF_TF_URG)
    {
        g_string_append_c(str, 'U');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (rflags & YF_TF_URG)
    {
        g_string_append_c(str, 'u');
    }
    else
    {
        g_string_append_c(str, '.');
    }

    if (flags & YF_TF_PSH)
    {
        g_string_append_c(str, 'P');
    }
    else
    {
        g_string_append_c(str, '.');
    }
    if (rflags & YF_TF_PSH)
    {
        g_string_append_c(str, 'p');
    }
    else
    {
        g_string_append_c(str, '.');
    }
}

static void print_ndpi(GString *rstr,
                       struct ndpi_detection_module_struct *ndpi_ctx,
                       uint16_t ndpi_master,
                       uint16_t ndpi_sub)
{
    char protocol_buf[128];
    char lowercase_label[256];
    ndpi_protocol protocol;
    protocol.master_protocol = ndpi_master;
    protocol.app_protocol = ndpi_sub;
    protocol.protocol_by_ip = 0;
    protocol.custom_category_userdata = NULL;
    char *appid = ndpi_protocol2name(ndpi_ctx, protocol, protocol_buf, sizeof(protocol_buf) - 1);

    strncpy(lowercase_label, appid, sizeof(lowercase_label) - 1);
    for (int i = 0; lowercase_label[i]; i++)
    {
        lowercase_label[i] = tolower(lowercase_label[i]);
    }
    g_string_append_printf(rstr, "%s", lowercase_label);
}

static int is_private_address(const char *ip)
{
    if (strstr(ip, "10.") ||
        strstr(ip, "172.16.") ||
        strstr(ip, "192.168."))
        return 1;
    return 0;
}

static const char *to_lower(char *str)
{
    char c;
    const char *ptr = str;

    while (*str)
    {
        c = *str;
        if (c >= 'A' && c <= 'Z')
            *str = c - ('A' - 'a');
        str++;
    }
    return ptr;
}

static int append_yaf_record(duckdb_appender appender,
                             const char *observation,
                             struct ndpi_detection_module_struct *ndpi_ctx,
                             const YAF_FLOW_RECORD *flow,
                             MMDB_s *asn_mmdb,
                             MMDB_s *country_mmdb)
{
    char sabuf[64], dabuf[64];

    GString *buffer = g_string_sized_new(256);

    duckdb_append_varchar(appender, observation);
    duckdb_timestamp start = {(flow->flowStartMilliseconds * 1000)};
    duckdb_append_timestamp(appender, start);
    duckdb_timestamp end = {(flow->flowEndMilliseconds * 1000)};
    duckdb_append_timestamp(appender, end);
    duckdb_append_uint32(appender, (flow->flowEndMilliseconds - flow->flowStartMilliseconds)); // duration
    duckdb_append_uint32(appender, flow->reverseFlowDeltaMilliseconds);

    double pcr = 0.0;
    if ((flow->dataByteCount + flow->reverseDataByteCount) != 0)
    {
        /*
        ( SrcApplicationBytes - DstApplicationBytes )
        PCR = ---------------------------------------------
        ( SrcApplicationBytes + DstApplicationBytes )
        */
        pcr = ((double)flow->dataByteCount - (double)flow->reverseDataByteCount) / ((double)flow->dataByteCount + (double)flow->reverseDataByteCount);
    }
    duckdb_append_float(appender, pcr);

    char proto_name[64];
    struct protoent *ptr = getprotobynumber(flow->protocolIdentifier);
    if (ptr)
        strncpy(proto_name, ptr->p_name, sizeof(proto_name) - 1);
    else
        snprintf(proto_name, sizeof(proto_name) - 1, "%u", flow->protocolIdentifier);

    duckdb_append_varchar(appender, proto_name);

    sabuf[0] = (char)0;
    dabuf[0] = (char)0;
    if (flow->sourceIPv4Address || flow->destinationIPv4Address)
    {
        air_ipaddr_buf_print(sabuf, flow->sourceIPv4Address);
        air_ipaddr_buf_print(dabuf, flow->destinationIPv4Address);
    }
    else
    {
        air_ip6addr_buf_print(sabuf, flow->sourceIPv6Address);
        air_ip6addr_buf_print(dabuf, flow->destinationIPv6Address);
    }

    duckdb_append_varchar(appender, sabuf);
    duckdb_append_varchar(appender, dabuf);
    duckdb_append_uint16(appender, flow->sourceTransportPort);
    duckdb_append_uint16(appender, flow->destinationTransportPort);

    /* print tcp flags */
    g_string_truncate(buffer, 0);
    print_tcp_flags(buffer, flow->initialTCPFlags, flow->reverseInitialTCPFlags);
    duckdb_append_varchar(appender, buffer->str);

    g_string_truncate(buffer, 0);
    print_tcp_flags(buffer, flow->unionTCPFlags, flow->reverseUnionTCPFlags);
    duckdb_append_varchar(appender, buffer->str);

    /* print tcp sequence numbers */
    duckdb_append_uint32(appender, flow->tcpSequenceNumber);
    duckdb_append_uint32(appender, flow->reverseTcpSequenceNumber);

    /* print vlan tags */
    if (flow->reverseOctetTotalCount)
    {
        duckdb_append_uint16(appender, flow->vlanId);
        duckdb_append_uint16(appender, flow->reverseVlanId);
    }
    else
    {
        duckdb_append_uint16(appender, flow->vlanId);
        duckdb_append_uint16(appender, 0);
    }

    /* print flow counters */
    duckdb_append_uint64(appender, flow->packetTotalCount);
    duckdb_append_uint64(appender, flow->reversePacketTotalCount);

    duckdb_append_uint64(appender, flow->octetTotalCount);
    duckdb_append_uint64(appender, flow->reverseOctetTotalCount);

    duckdb_append_uint8(appender, flow->entropy);
    duckdb_append_uint8(appender, flow->reverseEntropy);

    duckdb_append_uint64(appender, flow->averageInterarrivalTime);
    duckdb_append_uint64(appender, flow->reverseAverageInterarrivalTime);

    duckdb_append_uint64(appender, flow->standardDeviationInterarrivalTime);
    duckdb_append_uint64(appender, flow->reverseStandardDeviationInterarrivalTime);

    duckdb_append_uint32(appender, flow->tcpUrgTotalCount);
    duckdb_append_uint32(appender, flow->reverseTcpUrgTotalCount);

    duckdb_append_uint32(appender, flow->smallPacketCount);
    duckdb_append_uint32(appender, flow->reverseSmallPacketCount);

    duckdb_append_uint32(appender, flow->largePacketCount);
    duckdb_append_uint32(appender, flow->reverseLargePacketCount);

    duckdb_append_uint32(appender, flow->nonEmptyPacketCount);
    duckdb_append_uint32(appender, flow->reverseNonEmptyPacketCount);

    duckdb_append_uint16(appender, flow->firstNonEmptyPacketSize);
    duckdb_append_uint16(appender, flow->reverseFirstNonEmptyPacketSize);

    duckdb_append_uint16(appender, flow->maxPacketSize);
    duckdb_append_uint16(appender, flow->reverseMaxPacketSize);

    duckdb_append_uint16(appender, flow->standardDeviationPayloadLength);
    duckdb_append_uint16(appender, flow->reverseStandardDeviationPayloadLength);

    g_string_truncate(buffer, 0);
    g_string_append_printf(buffer, "%c%c%c%c%c%c%c%c%s",
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 7)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 6)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 5)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 4)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 3)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 2)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 1)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 0)) ? '1' : '0'),
                           YF_PRINT_DELIM);
    duckdb_append_varchar(appender, buffer->str);

    // ndpi
    g_string_truncate(buffer, 0);
    print_ndpi(buffer, ndpi_ctx, flow->ndpi_master, flow->ndpi_sub);
    duckdb_append_varchar(appender, buffer->str);

    /* end reason flags */
    g_string_truncate(buffer, 0);
    if ((flow->flowEndReason & YAF_END_MASK) == YAF_END_IDLE)
    {
        g_string_append(buffer, "idle");
    }
    if ((flow->flowEndReason & YAF_END_MASK) == YAF_END_ACTIVE)
    {
        g_string_append(buffer, "active");
    }
    if ((flow->flowEndReason & YAF_END_MASK) == YAF_END_FORCED)
    {
        g_string_append(buffer, "eof");
    }
    if ((flow->flowEndReason & YAF_END_MASK) == YAF_END_RESOURCE)
    {
        g_string_append(buffer, "rsrc");
    }
    if ((flow->flowEndReason & YAF_END_MASK) == YAF_END_UDPFORCE)
    {
        g_string_append(buffer, "force");
    }
    if (buffer->len == 0)
    {
        g_string_append(buffer, ".");
    }
    duckdb_append_varchar(appender, buffer->str);

    // smac
    g_string_truncate(buffer, 0);
    for (int loop = 0; loop < 6; loop++)
    {
        g_string_append_printf(buffer, "%02x", flow->sourceMacAddress[loop]);
        if (loop < 5)
        {
            g_string_append_printf(buffer, ":");
        }
    }
    duckdb_append_varchar(appender, buffer->str);

    // dmac
    g_string_truncate(buffer, 0);
    for (int loop = 0; loop < 6; loop++)
    {
        g_string_append_printf(buffer, "%02x",
                               flow->destinationMacAddress[loop]);
        if (loop < 5)
        {
            g_string_append_printf(buffer, ":");
        }
    }
    duckdb_append_varchar(appender, buffer->str);

    int gai_error, mmdb_error;
    MMDB_lookup_result_s result;

    int sprivate_address = is_private_address(sabuf);
    int dprivate_address = is_private_address(dabuf);

    char scountry[32] = {"private"};
    char dcountry[32] = {"private"};
    if (country_mmdb)
    {
        if (!sprivate_address)
        {
            result = MMDB_lookup_string(country_mmdb, sabuf, &gai_error, &mmdb_error);
            if (gai_error)
            {
                fprintf(stderr, "%s: Country getaddrinfo failed: %s", __FUNCTION__, gai_strerror(gai_error));
            }
            else if (mmdb_error)
            {
                fprintf(stderr, "%s: Country geopip lookup failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
            }
            else if (result.found_entry)
            {
                MMDB_entry_data_s entry_data;
                if (MMDB_get_value(&result.entry, &entry_data,
                                   "country", "iso_code", NULL) == MMDB_SUCCESS)
                {
                    if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING)
                    {
                        int len = entry_data.data_size > sizeof(scountry) ? (sizeof(scountry) - 1) : entry_data.data_size;
                        strncpy(scountry, entry_data.utf8_string, len);
                        scountry[len] = '\0';
                        to_lower(scountry);
                    }
                }
                else
                {
                    strncpy(scountry, "unk", sizeof(scountry) - 1);
                }
            }
        }

        if (!dprivate_address)
        {
            result = MMDB_lookup_string(country_mmdb, dabuf, &gai_error, &mmdb_error);
            if (gai_error)
            {
                fprintf(stderr, "%s: Country getaddrinfo failed: %s", __FUNCTION__, gai_strerror(gai_error));
            }
            else if (mmdb_error)
            {
                fprintf(stderr, "%s: Country geopip lookup failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
            }
            else if (result.found_entry)
            {
                MMDB_entry_data_s entry_data;
                if (MMDB_get_value(&result.entry, &entry_data,
                                   "country", "iso_code", NULL) == MMDB_SUCCESS)
                {
                    if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING)
                    {
                        int len = entry_data.data_size > sizeof(dcountry) ? (sizeof(dcountry) - 1) : entry_data.data_size;
                        strncpy(dcountry, entry_data.utf8_string, len);
                        dcountry[len] = '\0';
                        to_lower(dcountry);
                    }
                }
                else
                {
                    strncpy(scountry, "unk", sizeof(scountry) - 1);
                }
            }
        }
    }
    duckdb_append_varchar(appender, scountry);
    duckdb_append_varchar(appender, dcountry);

    uint32_t sasn = 0;
    uint32_t dasn = 0;
    char sasnorg[ASNORG_LEN] = {"private"};
    char dasnorg[ASNORG_LEN] = {"private"};
    if (asn_mmdb)
    {
        if (!sprivate_address)
        {
            result =
                MMDB_lookup_string(asn_mmdb, sabuf, &gai_error, &mmdb_error);
            if (gai_error)
            {
                fprintf(stderr, "%s: Country getaddrinfo failed: %s", __FUNCTION__, gai_strerror(gai_error));
            }
            else if (mmdb_error)
            {
                fprintf(stderr, "%s: Country geopip lookup failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
            }
            else if (result.found_entry)
            {
                MMDB_entry_data_s entry_data;
                if (MMDB_get_value(&result.entry, &entry_data,
                                   "autonomous_system_number", NULL) != MMDB_SUCCESS)
                {
                    fprintf(stderr, "%s: MMDB_get_value failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
                }
                if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UINT32)
                {
                    sasn = entry_data.uint32;
                }
                if (MMDB_get_value(&result.entry, &entry_data,
                                   "autonomous_system_organization", NULL) != MMDB_SUCCESS)
                {
                    fprintf(stderr, "%s: MMDB_get_value failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
                }
                if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING)
                {
                    int len = entry_data.data_size > sizeof(sasnorg) ? sizeof(sasnorg) - 1 : entry_data.data_size;
                    if (len > 0)
                    {
                        strncpy(sasnorg, entry_data.utf8_string, len);
                        sasnorg[len] = '\0';
                        to_lower(sasnorg);
                    }
                }
                else
                {
                    strncpy(sasnorg, "unk", sizeof(sasnorg) - 1);
                }
            }
        }

        if (!dprivate_address)
        {
            result =
                MMDB_lookup_string(asn_mmdb, dabuf, &gai_error, &mmdb_error);
            if (gai_error)
            {
                fprintf(stderr, "%s: Country getaddrinfo failed: %s", __FUNCTION__, gai_strerror(gai_error));
            }
            else if (mmdb_error)
            {
                fprintf(stderr, "%s: Country geopip lookup failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
            }
            else if (result.found_entry)
            {
                MMDB_entry_data_s entry_data;
                if (MMDB_get_value(&result.entry, &entry_data,
                                   "autonomous_system_number", NULL) != MMDB_SUCCESS)
                {
                    fprintf(stderr, "%s: MMDB_get_value failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
                }
                if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UINT32)
                {
                    dasn = entry_data.uint32;
                }
                if (MMDB_get_value(&result.entry, &entry_data,
                                   "autonomous_system_organization", NULL) != MMDB_SUCCESS)
                {
                    fprintf(stderr, "%s: MMDB_get_value failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
                }
                if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING)
                {
                    int len = entry_data.data_size > sizeof(dasnorg) ? sizeof(dasnorg) - 1 : entry_data.data_size;
                    if (len > 0)
                    {
                        strncpy(dasnorg, entry_data.utf8_string, len);
                        dasnorg[len] = '\0';
                        to_lower(dasnorg);
                    }
                }
                else
                {
                    strncpy(dasnorg, "unk", sizeof(dasnorg) - 1);
                }
            }
        }
    }

    duckdb_append_uint32(appender, sasn);
    duckdb_append_uint32(appender, dasn);
    duckdb_append_varchar(appender, sasnorg);
    duckdb_append_varchar(appender, dasnorg);

    char model_name[4] = {"na"};
    float score = 0.0;
    duckdb_append_varchar(appender, model_name); // model name
    duckdb_append_float(appender, score);  // score

    /* release scratch buffers */
    g_string_free(buffer, TRUE);

    return 0;
}

static int process_yaf_record(const char *observation,
                              duckdb_appender appender,
                              struct ndpi_detection_module_struct *ndpi_ctx,
                              const YAF_FLOW_RECORD *flow,
                              MMDB_s *asn_mmdb,
                              MMDB_s *country_mmdb)
{
    if (flow->protocolIdentifier > 0)
    {
        if (append_yaf_record(appender, observation, ndpi_ctx, flow, asn_mmdb, country_mmdb) < 0)
        {
            return -1;
        }

        if (duckdb_appender_end_row(appender) == DuckDBError)
        {
            fprintf(stderr, "%s: %s\n", __FUNCTION__, duckdb_appender_error(appender));
            return -1;
        }
    }
    return 0;
}

int yaf_import(const char *observation,
               const char *input_file,
               const char *output_dir,
               const char *asn_file,
               const char *country_file)
{
    int64_t flow_count = -1;
    GError *err = NULL;
    FILE *input_fp = NULL;
    duckdb_database db = NULL;
    duckdb_connection con = NULL;
    duckdb_result result;
    duckdb_appender appender = NULL;
    char *yaf_file_basename = NULL;
    struct ndpi_detection_module_struct *ndpi_ctx = NULL;
    MMDB_s asn_mmdb;
    MMDB_s *asn_mmdb_ptr = NULL;
    MMDB_s country_mmdb;
    MMDB_s *country_mmdb_ptr = NULL;
    fBuf_t *fbuf = NULL;
    fbCollector_t *collector = NULL;
    fbInfoModel_t *model = NULL;
    fbSession_t *session = NULL;
    fbTemplate_t *tmpl = NULL;
    char parquet_file[PATH_MAX];
    char tmp_file[PATH_MAX];
    char parquet_export_command[PATH_MAX * 2];
    YAF_FLOW_RECORD yaf_record;
    size_t yaf_rec_len = sizeof(yaf_record);

    do
    {
        // initialize ndpi
        {
            ndpi_ctx = ndpi_init_detection_module(0);
            if (ndpi_ctx == NULL)
            {
                fprintf(stderr, "%s: ndpi_init_detection_module() failed\n", __FUNCTION__);
                break;
            }

            NDPI_PROTOCOL_BITMASK protos;
            NDPI_BITMASK_SET_ALL(protos);
            ndpi_set_protocol_detection_bitmask2(ndpi_ctx, &protos);
            ndpi_finalize_initialization(ndpi_ctx);
        }

        // GeoIP stuff
        {
            //
            // maxmind ASN
            //
            memset(&asn_mmdb, 0, sizeof(asn_mmdb));
            if (asn_file && strlen(asn_file))
            {
                if (MMDB_SUCCESS != MMDB_open(asn_file, MMDB_MODE_MMAP, &asn_mmdb))
                {
                    fprintf(stderr, "%s: failed to load geolite - asn: %s\n", __FUNCTION__, asn_file);
                    break;
                }
                asn_mmdb_ptr = &asn_mmdb;
            }
            //
            // maxmind Country
            //
            memset(&country_mmdb, 0, sizeof(country_mmdb));
            if (country_file && strlen(country_file))
            {
                if (MMDB_SUCCESS != MMDB_open(country_file, MMDB_MODE_MMAP, &country_mmdb))
                {
                    fprintf(stderr, "%s: failed to load geolite - country: %s\n", __FUNCTION__, country_file);
                    break;
                }
                country_mmdb_ptr = &country_mmdb;
            }
        }

        // libfixbuf stuff
        {
            model = fbInfoModelAlloc();
            if (model == NULL)
                GLIB_ERROR_RETURN(err);
            fbInfoModelAddElementArray(model, yaf_enterprise_elements);

            tmpl = fbTemplateAlloc(model);
            if (tmpl == NULL)
                GLIB_ERROR_RETURN(err);

            if (fbTemplateAppendSpecArray(tmpl, yaf_flow_spec, YTF_ALL, &err) == FALSE)
                GLIB_ERROR_RETURN(err);

            session = fbSessionAlloc(model);
            if (session == NULL)
                GLIB_ERROR_RETURN(err);

            if (!fbSessionAddTemplate(session, TRUE, YAF_FLOW_FULL_TID, tmpl, NULL, &err))
                GLIB_ERROR_RETURN(err);

            if (input_file && strlen(input_file))
            {
                yaf_file_basename = basename(input_file);
                input_fp = fopen(input_file, "rb");
                if (input_fp == NULL)
                {
                    fprintf(stderr, "%s: error opening %s\n", __FUNCTION__, input_file);
                    break;
                }

                collector = fbCollectorAllocFP(NULL, input_fp);
                if (collector == NULL)
                    GLIB_ERROR_RETURN(err);

                fbuf = fBufAllocForCollection(session, collector);
                if (fbuf == NULL)
                    GLIB_ERROR_RETURN(err);

                if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, &err))
                    GLIB_ERROR_RETURN(err);

                memset(&yaf_record, 0, yaf_rec_len);
            }
            else
            {
                fprintf(stderr, "%s: missing input specifier\n", __FUNCTION__);
                break;
            }
        }

        //
        // duckdb stuff
        //
        if (output_dir && strlen(output_dir))
        {
            snprintf(tmp_file, sizeof(tmp_file) - 1, "%s/.%s", output_dir, yaf_file_basename);
            snprintf(parquet_file, sizeof(parquet_file) - 1, "%s/%s.parquet", output_dir, yaf_file_basename);
            snprintf(parquet_export_command, sizeof(parquet_export_command) - 1, " COPY (SELECT * FROM flow) TO '%s' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);", tmp_file);

            fprintf(stderr, "%s: input [%s]\n", __FUNCTION__, input_file);
            fprintf(stderr, "%s: output [%s]\n", __FUNCTION__, parquet_file);
            //
            //  initialize duckdb
            //
            duckdb_config config;

            // create the configuration object
            if (duckdb_create_config(&config) == DuckDBError)
            {
                fprintf(stderr, "%s: failed to create config object\n", __FUNCTION__);
                break;
            }
            // set some configuration options
            duckdb_set_config(config, "access_mode", "READ_WRITE"); // or READ_ONLY
            duckdb_set_config(config, "threads", "2");
            duckdb_set_config(config, "max_memory", "2GB");
            duckdb_set_config(config, "default_order", "DESC");

            // open the database using the configuration
            if (duckdb_open_ext(NULL, &db, config, NULL) == DuckDBError)
            {
                fprintf(stderr, "%s: error opening %s\n", __FUNCTION__, tmp_file);
                break;
            }
            // cleanup the configuration object
            duckdb_destroy_config(&config);

            if (duckdb_connect(db, &con) == DuckDBError)
            {
                fprintf(stderr, "%s: error connecting %s\n", __FUNCTION__, tmp_file);
                break;
            }

            if (duckdb_query(con, FLOW_SCHEMA, &result) == DuckDBError)
            {
                fprintf(stderr, "%s: failed to generating schema: \n%s\n", __FUNCTION__, duckdb_result_error(&result));
                break;
            }

            if (duckdb_appender_create(con, NULL, "flow", &appender) == DuckDBError)
            {
                fprintf(stderr, "%s: failed to create appender %s\n", __FUNCTION__, parquet_file);
                break;
            }
        }
        else
        {
            fprintf(stderr, "%s: missing output specifier\n", __FUNCTION__);
            break;
        }

        flow_count = 0;
        g_clear_error(&err);
        while (fBufNext(fbuf, (uint8_t *)&yaf_record, &yaf_rec_len, &err))
        {
            if (process_yaf_record(observation, appender, ndpi_ctx, &yaf_record, asn_mmdb_ptr, country_mmdb_ptr) < 0)
            {
                fprintf(stderr, "%s: %s", __FUNCTION__, strerror(errno));
                flow_count=-1;
                break;
            }
            flow_count++;
            memset(&yaf_record, 0, yaf_rec_len);
        }
        if (!g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_EOF))
            GLIB_ERROR_RETURN(err);

        duckdb_appender_flush(appender);
        duckdb_appender_destroy(&appender);

        if (flow_count > 0)
        {
            // write to parquet
            if (duckdb_query(con, parquet_export_command, &result) == DuckDBError)
            {
                fprintf(stderr, "%s: failed to generating parquet file: \n%s\n", __FUNCTION__, duckdb_result_error(&result));
                break;
            }

            if (rename(tmp_file, parquet_file) != 0)
            {
                fprintf(stderr, "%s: failed to rename file %s - %s \n", __FUNCTION__, tmp_file, strerror(errno));
                break;
            }
        }

    } while (0);

    //  This frees the Buffer, Session, Templates, and Collector.
    if (collector)
        fbCollectorClose(collector);
    if (tmpl)
        fbTemplateFreeUnused(tmpl);
    if (model)
        fbInfoModelFree(model);
    if (fbuf)
        fBufFree(fbuf);

    if (con)
        duckdb_disconnect(&con);
    if (db)
        duckdb_close(&db);

    if (asn_mmdb_ptr)
    {
        MMDB_close(&asn_mmdb);
    }
    if (country_mmdb_ptr)
    {
        MMDB_close(&country_mmdb);
    }

    if (ndpi_ctx)
        ndpi_exit_detection_module(ndpi_ctx);

    if (input_fp)
        fclose(input_fp);

    if (flow_count > 0)
        printf("%s: records [%lu]\n", __FUNCTION__, flow_count);
    else
        printf("%s: error [%lu]\n", __FUNCTION__, flow_count);

    return flow_count; // count
}


static gboolean
ycOpenDuckDBSink(
    MIOSource *source,
    MIOSink *sink,
    void *vctx,
    uint32_t *flags,
    GError **err)
{
    ycContext_t *yx = (ycContext_t *)vctx;

    /* start a new FixWriter */
    yx->obuf = yfWriterForFP(mio_fp(sink), 0, err);

    /* check for failure */
    if (yx->obuf)
    {
        /* Done. Get timestamp for file. */
        yx->outtime = time(NULL);
        ++yac_files;
        return TRUE;
    }
    else
    {
        *flags |= (MIO_F_CTL_SINKCLOSE | MIO_F_CTL_ERROR);
        return FALSE;
    }
}

static gboolean
ycCloseDuckDBSink(
    MIOSource *source,
    MIOSink *sink,
    void *vctx,
    uint32_t *flags,
    GError **err)
{
    ycContext_t *yx = (ycContext_t *)vctx;

    /* finish the message */
    if (yfWriterClose(yx->obuf, TRUE, err))
    {
        yx->obuf = NULL;
        return TRUE;
    }
    else
    {
        *flags |= MIO_F_CTL_ERROR;
        return FALSE;
    }
}

static gboolean
ycWriteDucKDBFlow(
    void *yfContext,
    yfFlow_t *flow,
    GError **err)
{

    uint32_t wtid;
    uint16_t etid = 0; /* extra templates */
    gboolean ok;
    int32_t temp = 0;
    int loop, count;
    yfContext_t *ctx = (yfContext_t *)yfContext;
    fBuf_t *fbuf = ctx->fbuf;

#if 0
    if (ctx->cfg->no_output)
    {
        return TRUE;
    }
    char sabuf[64], dabuf[64];

    GString *buffer = g_string_sized_new(256);

    duckdb_append_varchar(appender, observation);
    duckdb_timestamp start = {(flow->flowStartMilliseconds * 1000)};
    duckdb_append_timestamp(appender, start);
    duckdb_timestamp end = {(flow->flowEndMilliseconds * 1000)};
    duckdb_append_timestamp(appender, end);
    duckdb_append_uint32(appender, (flow->flowEndMilliseconds - flow->flowStartMilliseconds)); // duration
    duckdb_append_uint32(appender, flow->reverseFlowDeltaMilliseconds);

    double pcr = 0.0;
    if ((flow->dataByteCount + flow->reverseDataByteCount) != 0)
    {
        /*
        ( SrcApplicationBytes - DstApplicationBytes )
        PCR = ---------------------------------------------
        ( SrcApplicationBytes + DstApplicationBytes )
        */
        pcr = ((double)flow->dataByteCount - (double)flow->reverseDataByteCount) / ((double)flow->dataByteCount + (double)flow->reverseDataByteCount);
    }
    duckdb_append_float(appender, pcr);

    char proto_name[64];
    struct protoent *ptr = getprotobynumber(flow->protocolIdentifier);
    if (ptr)
        strncpy(proto_name, ptr->p_name, sizeof(proto_name) - 1);
    else
        snprintf(proto_name, sizeof(proto_name) - 1, "%u", flow->protocolIdentifier);

    duckdb_append_varchar(appender, proto_name);

    sabuf[0] = (char)0;
    dabuf[0] = (char)0;
    if (flow->sourceIPv4Address || flow->destinationIPv4Address)
    {
        air_ipaddr_buf_print(sabuf, flow->sourceIPv4Address);
        air_ipaddr_buf_print(dabuf, flow->destinationIPv4Address);
    }
    else
    {
        air_ip6addr_buf_print(sabuf, flow->sourceIPv6Address);
        air_ip6addr_buf_print(dabuf, flow->destinationIPv6Address);
    }

    duckdb_append_varchar(appender, sabuf);
    duckdb_append_varchar(appender, dabuf);
    duckdb_append_uint16(appender, flow->sourceTransportPort);
    duckdb_append_uint16(appender, flow->destinationTransportPort);

    /* print tcp flags */
    g_string_truncate(buffer, 0);
    print_tcp_flags(buffer, flow->initialTCPFlags, flow->reverseInitialTCPFlags);
    duckdb_append_varchar(appender, buffer->str);

    g_string_truncate(buffer, 0);
    print_tcp_flags(buffer, flow->unionTCPFlags, flow->reverseUnionTCPFlags);
    duckdb_append_varchar(appender, buffer->str);

    /* print tcp sequence numbers */
    duckdb_append_uint32(appender, flow->tcpSequenceNumber);
    duckdb_append_uint32(appender, flow->reverseTcpSequenceNumber);

    /* print vlan tags */
    if (flow->reverseOctetTotalCount)
    {
        duckdb_append_uint16(appender, flow->vlanId);
        duckdb_append_uint16(appender, flow->reverseVlanId);
    }
    else
    {
        duckdb_append_uint16(appender, flow->vlanId);
        duckdb_append_uint16(appender, 0);
    }

    /* print flow counters */
    duckdb_append_uint64(appender, flow->packetTotalCount);
    duckdb_append_uint64(appender, flow->reversePacketTotalCount);

    duckdb_append_uint64(appender, flow->octetTotalCount);
    duckdb_append_uint64(appender, flow->reverseOctetTotalCount);

    duckdb_append_uint8(appender, flow->entropy);
    duckdb_append_uint8(appender, flow->reverseEntropy);

    duckdb_append_uint64(appender, flow->averageInterarrivalTime);
    duckdb_append_uint64(appender, flow->reverseAverageInterarrivalTime);

    duckdb_append_uint64(appender, flow->standardDeviationInterarrivalTime);
    duckdb_append_uint64(appender, flow->reverseStandardDeviationInterarrivalTime);

    duckdb_append_uint32(appender, flow->tcpUrgTotalCount);
    duckdb_append_uint32(appender, flow->reverseTcpUrgTotalCount);

    duckdb_append_uint32(appender, flow->smallPacketCount);
    duckdb_append_uint32(appender, flow->reverseSmallPacketCount);

    duckdb_append_uint32(appender, flow->largePacketCount);
    duckdb_append_uint32(appender, flow->reverseLargePacketCount);

    duckdb_append_uint32(appender, flow->nonEmptyPacketCount);
    duckdb_append_uint32(appender, flow->reverseNonEmptyPacketCount);

    duckdb_append_uint16(appender, flow->firstNonEmptyPacketSize);
    duckdb_append_uint16(appender, flow->reverseFirstNonEmptyPacketSize);

    duckdb_append_uint16(appender, flow->maxPacketSize);
    duckdb_append_uint16(appender, flow->reverseMaxPacketSize);

    duckdb_append_uint16(appender, flow->standardDeviationPayloadLength);
    duckdb_append_uint16(appender, flow->reverseStandardDeviationPayloadLength);

    g_string_truncate(buffer, 0);
    g_string_append_printf(buffer, "%c%c%c%c%c%c%c%c%s",
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 7)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 6)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 5)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 4)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 3)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 2)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 1)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 0)) ? '1' : '0'),
                           YF_PRINT_DELIM);
    duckdb_append_varchar(appender, buffer->str);

    // ndpi
    g_string_truncate(buffer, 0);
    print_ndpi(buffer, ndpi_ctx, flow->ndpi_master, flow->ndpi_sub);
    duckdb_append_varchar(appender, buffer->str);

    /* end reason flags */
    g_string_truncate(buffer, 0);
    if ((flow->flowEndReason & YAF_END_MASK) == YAF_END_IDLE)
    {
        g_string_append(buffer, "idle");
    }
    if ((flow->flowEndReason & YAF_END_MASK) == YAF_END_ACTIVE)
    {
        g_string_append(buffer, "active");
    }
    if ((flow->flowEndReason & YAF_END_MASK) == YAF_END_FORCED)
    {
        g_string_append(buffer, "eof");
    }
    if ((flow->flowEndReason & YAF_END_MASK) == YAF_END_RESOURCE)
    {
        g_string_append(buffer, "rsrc");
    }
    if ((flow->flowEndReason & YAF_END_MASK) == YAF_END_UDPFORCE)
    {
        g_string_append(buffer, "force");
    }
    if (buffer->len == 0)
    {
        g_string_append(buffer, ".");
    }
    duckdb_append_varchar(appender, buffer->str);

    // smac
    g_string_truncate(buffer, 0);
    for (int loop = 0; loop < 6; loop++)
    {
        g_string_append_printf(buffer, "%02x", flow->sourceMacAddress[loop]);
        if (loop < 5)
        {
            g_string_append_printf(buffer, ":");
        }
    }
    duckdb_append_varchar(appender, buffer->str);

    // dmac
    g_string_truncate(buffer, 0);
    for (int loop = 0; loop < 6; loop++)
    {
        g_string_append_printf(buffer, "%02x",
                               flow->destinationMacAddress[loop]);
        if (loop < 5)
        {
            g_string_append_printf(buffer, ":");
        }
    }
    duckdb_append_varchar(appender, buffer->str);

    int gai_error, mmdb_error;
    MMDB_lookup_result_s result;

    int sprivate_address = is_private_address(sabuf);
    int dprivate_address = is_private_address(dabuf);

    char scountry[32] = {"private"};
    char dcountry[32] = {"private"};
    if (country_mmdb)
    {
        if (!sprivate_address)
        {
            result = MMDB_lookup_string(country_mmdb, sabuf, &gai_error, &mmdb_error);
            if (gai_error)
            {
                fprintf(stderr, "%s: Country getaddrinfo failed: %s", __FUNCTION__, gai_strerror(gai_error));
            }
            else if (mmdb_error)
            {
                fprintf(stderr, "%s: Country geopip lookup failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
            }
            else if (result.found_entry)
            {
                MMDB_entry_data_s entry_data;
                if (MMDB_get_value(&result.entry, &entry_data,
                                   "country", "iso_code", NULL) == MMDB_SUCCESS)
                {
                    if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING)
                    {
                        int len = entry_data.data_size > sizeof(scountry) ? (sizeof(scountry) - 1) : entry_data.data_size;
                        strncpy(scountry, entry_data.utf8_string, len);
                        scountry[len] = '\0';
                        to_lower(scountry);
                    }
                }
                else
                {
                    strncpy(scountry, "unk", sizeof(scountry) - 1);
                }
            }
        }

        if (!dprivate_address)
        {
            result = MMDB_lookup_string(country_mmdb, dabuf, &gai_error, &mmdb_error);
            if (gai_error)
            {
                fprintf(stderr, "%s: Country getaddrinfo failed: %s", __FUNCTION__, gai_strerror(gai_error));
            }
            else if (mmdb_error)
            {
                fprintf(stderr, "%s: Country geopip lookup failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
            }
            else if (result.found_entry)
            {
                MMDB_entry_data_s entry_data;
                if (MMDB_get_value(&result.entry, &entry_data,
                                   "country", "iso_code", NULL) == MMDB_SUCCESS)
                {
                    if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING)
                    {
                        int len = entry_data.data_size > sizeof(dcountry) ? (sizeof(dcountry) - 1) : entry_data.data_size;
                        strncpy(dcountry, entry_data.utf8_string, len);
                        dcountry[len] = '\0';
                        to_lower(dcountry);
                    }
                }
                else
                {
                    strncpy(scountry, "unk", sizeof(scountry) - 1);
                }
            }
        }
    }
    duckdb_append_varchar(appender, scountry);
    duckdb_append_varchar(appender, dcountry);

    uint32_t sasn = 0;
    uint32_t dasn = 0;
    char sasnorg[ASNORG_LEN] = {"private"};
    char dasnorg[ASNORG_LEN] = {"private"};
    if (asn_mmdb)
    {
        if (!sprivate_address)
        {
            result =
                MMDB_lookup_string(asn_mmdb, sabuf, &gai_error, &mmdb_error);
            if (gai_error)
            {
                fprintf(stderr, "%s: Country getaddrinfo failed: %s", __FUNCTION__, gai_strerror(gai_error));
            }
            else if (mmdb_error)
            {
                fprintf(stderr, "%s: Country geopip lookup failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
            }
            else if (result.found_entry)
            {
                MMDB_entry_data_s entry_data;
                if (MMDB_get_value(&result.entry, &entry_data,
                                   "autonomous_system_number", NULL) != MMDB_SUCCESS)
                {
                    fprintf(stderr, "%s: MMDB_get_value failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
                }
                if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UINT32)
                {
                    sasn = entry_data.uint32;
                }
                if (MMDB_get_value(&result.entry, &entry_data,
                                   "autonomous_system_organization", NULL) != MMDB_SUCCESS)
                {
                    fprintf(stderr, "%s: MMDB_get_value failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
                }
                if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING)
                {
                    int len = entry_data.data_size > sizeof(sasnorg) ? sizeof(sasnorg) - 1 : entry_data.data_size;
                    if (len > 0)
                    {
                        strncpy(sasnorg, entry_data.utf8_string, len);
                        sasnorg[len] = '\0';
                        to_lower(sasnorg);
                    }
                }
                else
                {
                    strncpy(sasnorg, "unk", sizeof(sasnorg) - 1);
                }
            }
        }

        if (!dprivate_address)
        {
            result =
                MMDB_lookup_string(asn_mmdb, dabuf, &gai_error, &mmdb_error);
            if (gai_error)
            {
                fprintf(stderr, "%s: Country getaddrinfo failed: %s", __FUNCTION__, gai_strerror(gai_error));
            }
            else if (mmdb_error)
            {
                fprintf(stderr, "%s: Country geopip lookup failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
            }
            else if (result.found_entry)
            {
                MMDB_entry_data_s entry_data;
                if (MMDB_get_value(&result.entry, &entry_data,
                                   "autonomous_system_number", NULL) != MMDB_SUCCESS)
                {
                    fprintf(stderr, "%s: MMDB_get_value failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
                }
                if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UINT32)
                {
                    dasn = entry_data.uint32;
                }
                if (MMDB_get_value(&result.entry, &entry_data,
                                   "autonomous_system_organization", NULL) != MMDB_SUCCESS)
                {
                    fprintf(stderr, "%s: MMDB_get_value failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
                }
                if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING)
                {
                    int len = entry_data.data_size > sizeof(dasnorg) ? sizeof(dasnorg) - 1 : entry_data.data_size;
                    if (len > 0)
                    {
                        strncpy(dasnorg, entry_data.utf8_string, len);
                        dasnorg[len] = '\0';
                        to_lower(dasnorg);
                    }
                }
                else
                {
                    strncpy(dasnorg, "unk", sizeof(dasnorg) - 1);
                }
            }
        }
    }

    duckdb_append_uint32(appender, sasn);
    duckdb_append_uint32(appender, dasn);
    duckdb_append_varchar(appender, sasnorg);
    duckdb_append_varchar(appender, dasnorg);

    char model_name[4] = {"na"};
    float score = 0.0;
    duckdb_append_varchar(appender, model_name); // model name
    duckdb_append_float(appender, score);        // score

    /* release scratch buffers */
    g_string_free(buffer, TRUE);
#endif
    return 0;
}

static gboolean
ycProcessDuckDB(
    MIOSource *source,
    MIOSink *sink,
    void *vctx,
    uint32_t *flags,
    GError **err)
{
    ycContext_t *yx = (ycContext_t *)vctx;
    fbListener_t *listener = (fbListener_t *)source->vsp;
    yfContext_t ctx = YF_CTX_INIT;
#if 1
    ctx.fbuf = yx->obuf;
   // ctx.cfg = &yaf_config;

    /* Check for end of output file */
    //if (yac_rotate && (time(NULL) > yx->outtime + yac_rotate))
   // {
   //     *flags |= MIO_F_CTL_SINKCLOSE;
   // }

    /* Check for quit */
    if (daec_did_quit())
    {
        *flags |= MIO_F_CTL_TERMINATE;
        return TRUE;
    }

    /* Check to see if we need to wait for a buffer */
    if (!yx->ibuf || !yx->ibuf_ready)
    {
        if (!(yx->ibuf = fbListenerWait(listener, err)))
        {
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD) ||
                g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_CONN))
            {
                /* FIXME this quits on any interrupt */
                daec_quit();
                g_critical("Error on read: %s", (*err)->message);
                g_clear_error(err);
                *flags |= MIO_F_CTL_TERMINATE;
                return TRUE;
            }
            else
            {
                return FALSE;
            }
        }
    }

    /* presume our buffer is ready and process a flow */
    yx->ibuf_ready = TRUE;
    if (yfReadFlowExtended(yx->ibuf, &(yx->flow), err))
    {
        /* Print it for debugging purposes */
        if (yx->pstr)
        {
            g_string_truncate(yx->pstr, 0);
        }
        else
        {
            yx->pstr = g_string_new(NULL);
        }
        yfPrintString(yx->pstr, &(yx->flow));
        //if (yac_printall)
        //{
        //    fprintf(stdout, "flow: %s", yx->pstr->str);
        //}

        /* Got a flow. Write it. */
        if (ycWriteDucKDBFlow(&ctx, &(yx->flow), err))
        {
            /* Read and written. Done. */
            ++yac_flows;
            return TRUE;
        }
        else
        {
            /* Write error. Fatal. */
            *flags |= MIO_F_CTL_ERROR;
            return FALSE;
        }
    }
    else
    {
        if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM))
        {
            /* End of message. Set ibuf not ready, keep going. */
            g_clear_error(err);
            yx->ibuf_ready = FALSE;
            return TRUE;
        }
        else if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD))
        {
            /* just keep going if the error is "no packet" */
            g_clear_error(err);
            return TRUE;
        }
        else
        {
            /* Close the buffer */
            fBufFree(yx->ibuf);
            yx->ibuf_ready = FALSE;
            yx->ibuf = NULL;

            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOF))
            {
                /* EOF on a single collector not an issue. */
                g_clear_error(err);
                g_debug("Normal connection close");
                return TRUE;
            }
            else
            {
                /* bad message. no doughnut. chuck it but keep the socket. */
                sink->active = FALSE;
                *flags |= MIO_F_CTL_ERROR;
                return FALSE;
            }
        }
    }
#endif    
}

static fbConnSpec_t yac_inspec = FB_CONNSPEC_INIT;

static gboolean
ycOpenListener(
    MIOSource *source,
    void *vctx,
    uint32_t *flags,
    GError **err)
{
    /* create listener */
    if (!(source->vsp = yfListenerForSpec(&yac_inspec, NULL,
                                          NULL, err)))
    {
        *flags |= (MIO_F_CTL_ERROR | MIO_F_CTL_TERMINATE);
        return FALSE;
    }

    return TRUE;
}

static gboolean
ycCloseListener(
    MIOSource *source,
    void *vctx,
    uint32_t *flags,
    GError **err)
{
    /* FIXME should shut the listener down perhaps? */

    return TRUE;
}


int gnat_collector(
    int argc,
    char *argv[])
{
    GError *err = NULL;
    ycContext_t yx;
    MIOSource source;
    MIOSink sink;
    MIOAppDriver adrv;
    uint32_t miodflags;
    int rv = 0;
    
    int yac_rotate = 300;
    char *yac_transport = NULL;
    gboolean yac_tls = FALSE;
    gboolean yac_printall = FALSE;    


    /* parse options */

    // TODO: convert to YAML file
    //ycParseOptions(&argc, &argv);

    /* set up logging */
    if (!logc_setup(&err))
    {
        air_opterr("%s", err->message);
    }

    /* fork if necessary */
    if (!daec_setup(&err))
    {
        air_opterr("%s", err->message);
    }

    /* initialize MIO flags */
    miodflags = 0;

    /* default port */
    if (!yac_inspec.svc)
    {
        yac_inspec.svc = g_strdup(yac_tls ? "4740" : "4739");
    }

    if (!yac_transport)
    {
        yac_transport = strdup("tcp");
    }

    if (strcmp(yac_transport, "tcp") == 0)
    {
        if (yac_tls)
        {
            yac_inspec.transport = FB_TLS_TCP;
        }
        else
        {
            yac_inspec.transport = FB_TCP;
        }
    }
    else if (strcmp(yac_transport, "udp") == 0)
    {
        if (yac_tls)
        {
            yac_inspec.transport = FB_DTLS_UDP;
        }
        else
        {
            yac_inspec.transport = FB_UDP;
        }
    }
    else if (strcmp(yac_transport, "sctp") == 0)
    {
        if (yac_tls)
        {
            yac_inspec.transport = FB_DTLS_SCTP;
        }
        else
        {
            yac_inspec.transport = FB_SCTP;
        }
    }
    else
    {
        air_opterr("Unsupported IPFIX transport protocol %s", yac_transport);
    }

    /* create a source around a listener */
    if (!mio_source_init_app(&source, mio_ov_in, MIO_T_APP, NULL, &err))
    {
        air_opterr("Cannot set up MIO input: %s", err->message);
    }

    /* initialize yafcollect context */
    yfFlowPrepare(&(yx.flow));
    yx.obuf = NULL;
    yx.ibuf = NULL;
    yx.ibuf_ready = FALSE;
    yx.pstr = NULL;
    yx.outtime = 0;

    /* set up an app driver */
    adrv.app_open_source = ycOpenListener;
    adrv.app_close_source = ycCloseListener;

    // callback to Rust functions
    adrv.app_open_sink = ycOpenDuckDBSink;
    adrv.app_close_sink = ycCloseDuckDBSink;
    adrv.app_process = ycProcessDuckDB;

    g_message("gnat_collector starting up");

    /* do dispatch here */
    if (!mio_dispatch_loop(&source, &sink, &adrv, &yx, miodflags, mio_ov_poll,
                           1, mio_ov_poll))
    {
        rv = 1;
    }

    g_message("gnat_collector: shutting down");
    g_message("gnat_collector: processed %u flows into %u files", yac_flows, yac_files);

    return rv;
}
