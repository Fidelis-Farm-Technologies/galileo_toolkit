
/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

#include "yaf_record.h"
#include "import_libfixbuf.h"
#include "export_parquet.h"
#include "io_context.h"

static void
PrintTCPFlags(
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

static void PrintNDPI(GString *rstr,
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

static int IsPrivateAddress(const char *ip)
{
    if (strstr(ip, "10.") ||
        strstr(ip, "172.16.") ||
        strstr(ip, "192.168."))
        return 1;
    return 0;
}

static const char *ToLowerString(char *str)
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

static int AppendIpfixRecord(duckdb_appender appender,
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
    PrintTCPFlags(buffer, flow->initialTCPFlags, flow->reverseInitialTCPFlags);
    duckdb_append_varchar(appender, buffer->str);

    g_string_truncate(buffer, 0);
    PrintTCPFlags(buffer, flow->unionTCPFlags, flow->reverseUnionTCPFlags);
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
                           "|");
    duckdb_append_varchar(appender, buffer->str);

    // ndpi
    g_string_truncate(buffer, 0);
    PrintNDPI(buffer, ndpi_ctx, flow->ndpi_master, flow->ndpi_sub);
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

    int sprivate_address = IsPrivateAddress(sabuf);
    int dprivate_address = IsPrivateAddress(dabuf);

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
                        ToLowerString(scountry);
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
                        ToLowerString(dcountry);
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
                        ToLowerString(sasnorg);
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
                        ToLowerString(dasnorg);
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

    return 0;
}

static int WriteIpfixRecord(const char *observation,
                            duckdb_appender appender,
                            struct ndpi_detection_module_struct *ndpi_ctx,
                            const YAF_FLOW_RECORD *flow,
                            MMDB_s *asn_mmdb,
                            MMDB_s *country_mmdb)
{
    if (flow->protocolIdentifier > 0)
    {
        if (AppendIpfixRecord(appender, observation, ndpi_ctx, flow, asn_mmdb, country_mmdb) < 0)
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

// ------------------------------------------------------------------------------------------------------
//
// ------------------------------------------------------------------------------------------------------

gboolean
OpenFileSink(
    MIOSource *source,
    MIOSink *sink,
    void *ctx,
    uint32_t *flags,
    GError **err)
{
    do
    {
        GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;
        if (!gnat)
            break;

        // initialize ndpi
        {
            gnat->ndpi_ctx = ndpi_init_detection_module(0);
            if (gnat->ndpi_ctx == NULL)
            {
                fprintf(stderr, "%s: ndpi_init_detection_module() failed\n", __FUNCTION__);
                break;
            }

            NDPI_PROTOCOL_BITMASK protos;
            NDPI_BITMASK_SET_ALL(protos);
            ndpi_set_protocol_detection_bitmask2(gnat->ndpi_ctx, &protos);
            ndpi_finalize_initialization(gnat->ndpi_ctx);
        }

        // GeoIP stuff
        {
            //
            // maxmind ASN
            //
            memset(&gnat->asn_mmdb, 0, sizeof(gnat->asn_mmdb));
            if (gnat->asn_file && strlen(gnat->asn_file))
            {
                if (MMDB_SUCCESS != MMDB_open(gnat->asn_file, MMDB_MODE_MMAP, &gnat->asn_mmdb))
                {
                    fprintf(stderr, "%s: failed to load geolite - asn: %s\n", __FUNCTION__, gnat->asn_file);
                    break;
                }
                gnat->asn_mmdb_ptr = &gnat->asn_mmdb;
            }
            //
            // maxmind Country
            //
            memset(&gnat->country_mmdb, 0, sizeof(gnat->country_mmdb));
            if (gnat->country_file && strlen(gnat->country_file))
            {
                if (MMDB_SUCCESS != MMDB_open(gnat->country_file, MMDB_MODE_MMAP, &gnat->country_mmdb))
                {
                    fprintf(stderr, "%s: failed to load geolite - country: %s\n", __FUNCTION__, gnat->country_file);
                    break;
                }
                gnat->country_mmdb_ptr = &gnat->country_mmdb;
            }
        }

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
        if (duckdb_open_ext(NULL, &gnat->db, config, NULL) == DuckDBError)
        {
            fprintf(stderr, "%s: failed to open db\n", __FUNCTION__);
            break;
        }
        // cleanup the configuration object
        duckdb_destroy_config(&config);

        if (duckdb_connect(gnat->db, &gnat->con) == DuckDBError)
        {
            fprintf(stderr, "%s: failed to connect to db\n", __FUNCTION__);
            break;
        }
        duckdb_result db_result;
        if (duckdb_query(gnat->con, FLOW_SCHEMA, &db_result) == DuckDBError)
        {
            fprintf(stderr, "%s: failed to generating schema: \n%s\n", __FUNCTION__, duckdb_result_error(&db_result));
            break;
        }

        if (duckdb_appender_create(gnat->con, NULL, "flow", &gnat->appender) == DuckDBError)
        {
            fprintf(stderr, "%s: failed to create appender\n", __FUNCTION__);
            break;
        }

        gnat->outtime = time(NULL);
        ++gnat->ipfix_files;

        return TRUE;

    } while (0);

    *flags |= (MIO_F_CTL_SINKCLOSE | MIO_F_CTL_ERROR);
    return FALSE;
}

gboolean
RotateFileSink(MIOSource *source,
               MIOSink *sink,
               void *ctx,
               uint32_t *flags,
               GError **err)
{
    gboolean status = FALSE;
    char file_name[PATH_MAX / 2];
    char tmp_file[(PATH_MAX * 2) + 1];
    char parquet_file[PATH_MAX];
    char parquet_export_command[(PATH_MAX * 3) + 1];

    do
    {
        GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;
        if (!gnat)
            break;

        if (gnat->ipfix_flows <= 0)
        {
            break;
        }
        if (!gnat->output_dir || strlen(gnat->output_dir) <= 0)
        {
            fprintf(stderr, "%s: missing output specifier\n", __FUNCTION__);
            break;
        }

        duckdb_appender_flush(gnat->appender);
        duckdb_appender_destroy(&gnat->appender);

        snprintf(file_name, sizeof(file_name) - 1, ".%s.%u", gnat->observation, gnat->outtime);
        snprintf(tmp_file, sizeof(tmp_file) - 1, "%s/%s", gnat->output_dir, file_name);
        snprintf(parquet_file, sizeof(parquet_file) - 1, "%s/gnat%s.parquet", gnat->output_dir, file_name);
        snprintf(parquet_export_command, sizeof(parquet_export_command) - 1, " COPY (SELECT * FROM flow) TO '%s' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);", tmp_file);

        fprintf(stderr, "%s: output [%s]\n", __FUNCTION__, parquet_file);

        if (gnat->ipfix_flows > 0)
        {
            duckdb_result db_result;
            // write to parquet
            if (duckdb_query(gnat->con, parquet_export_command, &db_result) == DuckDBError)
            {
                fprintf(stderr, "%s: failed to generating parquet file: \n%s\n", __FUNCTION__, duckdb_result_error(&db_result));
                break;
            }

            if (rename(tmp_file, parquet_file) != 0)
            {
                fprintf(stderr, "%s: failed to rename file %s - %s \n", __FUNCTION__, tmp_file, strerror(errno));
                break;
            }
        }

        if (gnat->con)
            duckdb_disconnect(&gnat->con);
        if (gnat->db)
            duckdb_close(&gnat->db);

        status = TRUE;
    } while (0);

    return status;
}

gboolean
CloseFileSink(
    MIOSource *source,
    MIOSink *sink,
    void *ctx,
    uint32_t *flags,
    GError **err)
{
    gboolean status = FALSE;
    char file_name[PATH_MAX / 2];
    char tmp_file[(PATH_MAX * 2) + 1];
    char parquet_file[PATH_MAX];
    char parquet_export_command[(PATH_MAX * 3) + 1];
    do
    {
        GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;
        if (!gnat)
            break;

        duckdb_appender_flush(gnat->appender);
        duckdb_appender_destroy(&gnat->appender);

        if (gnat->output_dir && strlen(gnat->output_dir))
        {
            snprintf(file_name, sizeof(file_name) - 1, ".%s.%u", gnat->observation, gnat->outtime);
            snprintf(tmp_file, sizeof(tmp_file) - 1, "%s/%s", gnat->output_dir, file_name);
            snprintf(parquet_file, sizeof(parquet_file) - 1, "%s/gnat%s.parquet", gnat->output_dir, file_name);
            snprintf(parquet_export_command, sizeof(parquet_export_command) - 1, " COPY (SELECT * FROM flow) TO '%s' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);", tmp_file);

            // fprintf(stderr, "%s: input [%s]\n", __FUNCTION__, input_file);
            fprintf(stderr, "%s: output [%s]\n", __FUNCTION__, parquet_file);
        }
        else
        {
            fprintf(stderr, "%s: missing output specifier\n", __FUNCTION__);
            break;
        }

        if (gnat->ipfix_flows > 0)
        {
            duckdb_result db_result;
            // write to parquet
            if (duckdb_query(gnat->con, parquet_export_command, &db_result) == DuckDBError)
            {
                fprintf(stderr, "%s: failed to generating parquet file: \n%s\n", __FUNCTION__, duckdb_result_error(&db_result));
                break;
            }

            if (rename(tmp_file, parquet_file) != 0)
            {
                fprintf(stderr, "%s: failed to rename file %s - %s \n", __FUNCTION__, tmp_file, strerror(errno));
                break;
            }
        }

        if (gnat->con)
            duckdb_disconnect(&gnat->con);
        if (gnat->db)
            duckdb_close(&gnat->db);

        if (gnat->asn_mmdb_ptr)
        {
            MMDB_close(&gnat->asn_mmdb);
        }
        if (gnat->country_mmdb_ptr)
        {
            MMDB_close(&gnat->country_mmdb);
        }

        if (gnat->ndpi_ctx)
            ndpi_exit_detection_module(gnat->ndpi_ctx);

        if (gnat->ipfix_flows > 0)
            printf("%s: records [%lu]\n", __FUNCTION__, gnat->ipfix_flows);
        else
            printf("%s: error [%lu]\n", __FUNCTION__, gnat->ipfix_flows);

        status = TRUE;
    } while (0);

    if (status == FALSE)
        *flags |= MIO_F_CTL_ERROR;
    return status;
}

gboolean
ReaderToFileSink(
    MIOSource *source,
    MIOSink *sink,
    void *ctx,
    uint32_t *flags,
    GError **err)
{
    GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;

    /* presume our buffer is ready and process a flow */
    YAF_FLOW_RECORD ipfix_record;
    size_t yaf_rec_len = sizeof(ipfix_record);
    while (fBufNext(gnat->input_buf, (uint8_t *)&ipfix_record, &yaf_rec_len, err))
    {
        if (WriteIpfixRecord(gnat->observation,
                             gnat->appender,
                             gnat->ndpi_ctx,
                             &ipfix_record,
                             &gnat->asn_mmdb,
                             &gnat->country_mmdb) < 0)

        {
            gnat->ipfix_flows = -1;
            sink->active = FALSE;
            *flags |= (MIO_F_CTL_SINKCLOSE | MIO_F_CTL_ERROR);
            return FALSE;
        }
        ++gnat->ipfix_flows;
        memset(&ipfix_record, 0, yaf_rec_len);
        fprintf(stderr, "%s:\n", __FUNCTION__);
    }

    if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOF))
    {
        /* EOF on a single collector not an issue. */
        sink->active = FALSE;
        *flags |= (MIO_F_CTL_SINKCLOSE);
        g_clear_error(err);
        return TRUE;
    }
    else
    {
        /* bad message */
        sink->active = FALSE;
        *flags |= (MIO_F_CTL_SINKCLOSE | MIO_F_CTL_ERROR);
        return FALSE;
    }
}

gboolean
SocketToFileSink(
    MIOSource *source,
    MIOSink *sink,
    void *ctx,
    uint32_t *flags,
    GError **err)
{
    GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;

    /* Check for end of output file */
    if (gnat->rotate_interval && (time(NULL) > gnat->outtime + gnat->rotate_interval))
    {
        // TODO: export file
        sink->active = FALSE;
        *flags |= MIO_F_CTL_SINKCLOSE;
    }

    /* Check for quit */
    if (daec_did_quit())
    {
        *flags |= MIO_F_CTL_TERMINATE;
        return TRUE;
    }

    /* Check to see if we need to wait for a buffer */
    if (!gnat->input_buf || !gnat->input_buf_ready)
    {
        if (!(gnat->input_buf = fbListenerWait(gnat->listener, err)))
        {
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD) ||
                g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_CONN))
            {
                /* FIXME this quits on any interrupt */
                daec_quit();
                g_critical("gnat_collector: error on read -- %s", (*err)->message);
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
    gnat->input_buf_ready = TRUE;
    YAF_FLOW_RECORD ipfix_record;
    size_t yaf_rec_len = sizeof(ipfix_record);
    while (fBufNext(gnat->input_buf, (uint8_t *)&ipfix_record, &yaf_rec_len, err))
    {
        if (WriteIpfixRecord(gnat->observation,
                             gnat->appender,
                             gnat->ndpi_ctx,
                             &ipfix_record,
                             &gnat->asn_mmdb,
                             &gnat->country_mmdb) < 0)

        {
            gnat->ipfix_flows = -1;
            sink->active = FALSE;
            *flags |= MIO_F_CTL_ERROR;
            return FALSE;
        }
        ++gnat->ipfix_flows;
        memset(&ipfix_record, 0, yaf_rec_len);
    }
    //}

    if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM))
    {
        /* End of message. Set input_buf not ready, keep going. */
        g_clear_error(err);
        gnat->input_buf_ready = FALSE;
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
        fBufFree(gnat->input_buf);
        gnat->input_buf_ready = FALSE;
        gnat->input_buf = NULL;

        if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOF))
        {
            /* EOF on a single collector not an issue. */
            g_clear_error(err);
            g_debug("gnat_collector: normal connection close");
            sink->active = FALSE;
            *flags |= MIO_F_CTL_SINKCLOSE;
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
