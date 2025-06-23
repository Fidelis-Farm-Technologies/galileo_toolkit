/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

#include <math.h>
#include "yaf_record.h"
#include "import_libfixbuf.h"
#include "export_parquet.h"
#include "io_context.h"

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

static void
PrintTCPFlags(
    GString *str,
    uint8_t flags,
    uint8_t rflags)
{
    // Syn - Ss
    // Ack - Aa
    // Rset - Rr
    // Fin - Ff
    // Checksum - Cc
    // Urgent - Uu
    // Push - Pp
    // Explicit Congestion Notification - Ee

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
}

static void PrintNDPI(GString *rstr,
                      struct ndpi_detection_module_struct *ndpi_ctx,
                      ndpi_protocol protocol)
{
    char protocol_buf[128];
    char lowercase_tag[256];

    char *appid = ndpi_protocol2name(ndpi_ctx, protocol, protocol_buf, sizeof(protocol_buf) - 1);

    strncpy(lowercase_tag, appid, sizeof(lowercase_tag) - 1);
    for (int i = 0; lowercase_tag[i]; i++)
    {
        lowercase_tag[i] = tolower(lowercase_tag[i]);
    }
    g_string_append_printf(rstr, "%s", lowercase_tag);
}

static void PrintNDPICategory(GString *rstr,
                              struct ndpi_detection_module_struct *ndpi_ctx,
                              ndpi_protocol protocol)
{
    char lowercase_category[256];

    ndpi_protocol_category_t category_id = ndpi_get_proto_category(ndpi_ctx, protocol);

    const char *category_str = ndpi_category_get_name(ndpi_ctx, category_id);

    strncpy(lowercase_category, category_str, sizeof(lowercase_category) - 1);
    for (int i = 0; lowercase_category[i]; i++)
    {
        lowercase_category[i] = tolower(lowercase_category[i]);
    }
    g_string_append_printf(rstr, "%s", lowercase_category);
}

static int IsPrivateAddress(const char *ip)
{
    if (ip[0] == '1')
    {
        // 10.x.x.x
        if (ip[1] == '0' && ip[2] == '.')
            return 1;
        // 192.168.x.x
        if (ip[1] == '9' && ip[2] == '2' && ip[3] == '.' &&
            ip[4] == '1' && ip[5] == '6' && ip[6] == '8' && ip[7] == '.')
            return 1;
        // 172.16.x.x. to 172.31.x.x
        if (ip[1] == '7' && ip[2] == '2' && ip[3] == '.')
        {
            if (ip[4] == '1' && ip[6] == '.')
            {
                if (ip[5] == '6' || ip[5] == '7' || ip[5] == '8' || ip[5] == '9')
                    return 1;
            }
            else if (ip[4] == '2' && ip[6] == '.')
            {
                if (ip[5] == '0' || ip[5] == '1' || ip[5] == '2' || ip[5] == '3' || ip[5] == '4' ||
                    ip[5] == '5' || ip[5] == '6' || ip[5] == '7' || ip[5] == '8' || ip[5] == '9')
                    return 1;
            }
            else if (ip[4] == '3' && ip[6] == '.')
            {
                if (ip[5] == '0' || ip[5] == '1')
                    return 1;
            }
        }
    }
    return 0;
}
static int IsMulticastAddress(uint32_t ip)
{
    // see https://en.wikipedia.org/wiki/Multicast_address
#define MULTICAST_MASK 0xE0000000 // 11100000000000000000000000000000
    return ((ip & MULTICAST_MASK) == MULTICAST_MASK) ? 1 : 0;
}

static int IsBroadcastAddress(uint32_t ip)
{
#define BROADCAST_MASK 0xFF000000
    return ((ip & BROADCAST_MASK) == BROADCAST_MASK) ? 1 : 0;
}

#define PARQUET_FLOW_SCHEMA_VERSION 3

static int AppendIpfixRecord(duckdb_appender appender,
                             const char *observation,
                             struct ndpi_detection_module_struct *ndpi_ctx,
                             const YAF_FLOW_RECORD *flow,
                             MMDB_s *asn_mmdb,
                             MMDB_s *country_mmdb,
                             uint16_t risk_threshold)
{
    // Defensive: validate parameters
    if (!appender || !observation || !flow)
    {
        fprintf(stderr, "%s: invalid parameters\n", __FUNCTION__);
        return -1;
    }
    char sabuf[64], dabuf[64];
    GString *buffer = g_string_sized_new(256);
    GString *category = g_string_sized_new(64);
    if (!buffer || !category)
    {
        fprintf(stderr, "%s: failed to allocate GString buffers\n", __FUNCTION__);
        if (buffer)
            g_string_free(buffer, 1);
        if (category)
            g_string_free(category, 1);
        return -1;
    }

    g_string_truncate(buffer, 0);
    g_string_truncate(category, 0);

    duckdb_append_uint32(appender, PARQUET_FLOW_SCHEMA_VERSION);
    duckdb_append_null(appender); // UUID
    duckdb_append_varchar(appender, observation);
    duckdb_timestamp start = {(flow->flowStartMilliseconds * 1000)};
    duckdb_append_timestamp(appender, start);
    duckdb_timestamp end = {(flow->flowEndMilliseconds * 1000)};
    duckdb_append_timestamp(appender, end);
    duckdb_append_uint32(appender, (flow->flowEndMilliseconds - flow->flowStartMilliseconds)); // duration
    duckdb_append_uint32(appender, flow->reverseFlowDeltaMilliseconds);

    uint32_t pcr = 0;
    if ((flow->dataByteCount + flow->reverseDataByteCount) != 0)
    {
        /*
        ( SrcApplicationBytes - DstApplicationBytes )
        PCR = ---------------------------------------------
        ( SrcApplicationBytes + DstApplicationBytes )
        */
        float pcr_float = ((float)flow->dataByteCount - (float)flow->reverseDataByteCount) / ((float)flow->dataByteCount + (float)flow->reverseDataByteCount);
        pcr = (uint32_t)round(pcr_float * 10); // PCR in tenths
    }
    duckdb_append_int32(appender, pcr);

    // --- String handling best practice: always null-terminate after strncpy ---
    char proto_name[64] = {0};
    struct protoent *ptr = getprotobynumber(flow->protocolIdentifier);
    if (ptr)
    {
        strncpy(proto_name, ptr->p_name, sizeof(proto_name) - 1);
        proto_name[sizeof(proto_name) - 1] = '\0';
    }
    else
    {
        snprintf(proto_name, sizeof(proto_name), "%u", flow->protocolIdentifier);
    }
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
    g_string_append_printf(buffer, "%c%c%c%c%c%c%c%c",
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 7)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 6)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 5)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 4)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 3)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 2)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 1)) ? '1' : '0'),
                           ((flow->firstEightNonEmptyPacketDirections & (1 << 0)) ? '1' : '0'));
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
    // --- String handling best practice: orientation buffer ---
    char orientation[4] = {0}; // "ii", "io", "oi", "oo"
    strncat(orientation, sprivate_address ? "i" : "o", sizeof(orientation) - strlen(orientation) - 1);
    strncat(orientation, dprivate_address ? "i" : "o", sizeof(orientation) - strlen(orientation) - 1);

    char scountry[32] = {"na"};
    char dcountry[32] = {"na"};
    if (country_mmdb)
    {
        if (!sprivate_address)
        {
            result = MMDB_lookup_string(country_mmdb, sabuf, &gai_error, &mmdb_error);
            if (gai_error)
            {
                fprintf(stderr, "%s: country getaddrinfo failed: %s", __FUNCTION__, gai_strerror(gai_error));
            }
            else if (mmdb_error)
            {
                fprintf(stderr, "%s: country geopip lookup failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
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
            }
        }
        else
        {
            strncpy(scountry, "private", sizeof(scountry) - 1);
        }

        if (!dprivate_address)
        {
            result = MMDB_lookup_string(country_mmdb, dabuf, &gai_error, &mmdb_error);
            if (gai_error)
            {
                fprintf(stderr, "%s: country getaddrinfo failed: %s", __FUNCTION__, gai_strerror(gai_error));
            }
            else if (mmdb_error)
            {
                fprintf(stderr, "%s: country geopip lookup failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
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
            }
        }
        else
        {
            strncpy(dcountry, "private", sizeof(scountry) - 1);
        }
    }

    duckdb_append_varchar(appender, scountry);
    duckdb_append_varchar(appender, dcountry);

    uint32_t sasn = 0;
    uint32_t dasn = 0;
    char sasnorg[ASNORG_LEN] = {"na"};
    char dasnorg[ASNORG_LEN] = {"na"};

    if (asn_mmdb)
    {
        int smulticast = 0;
        int dmulticast = 0;
        int sbroadcast = 0;
        int dbroadcast = 0;
        if (flow->sourceIPv4Address)
        {
            smulticast = IsMulticastAddress(flow->sourceIPv4Address);
            if (sprivate_address)
            {
                strncpy(sasnorg, "private", sizeof(sasnorg) - 1);
            }
            else if (smulticast)
            {
                strncpy(sasnorg, "multicast", ASNORG_LEN);
            }
            else
            {
                sbroadcast = IsBroadcastAddress(flow->sourceIPv4Address);
                if (sbroadcast)
                {
                    strncpy(sasnorg, "broadcast", ASNORG_LEN);
                }
            }
        }
        if (flow->destinationIPv4Address)
        {
            dmulticast = IsMulticastAddress(flow->destinationIPv4Address);
            if (dprivate_address)
            {
                strncpy(dasnorg, "private", sizeof(dasnorg) - 1);
            }
            else if (dmulticast)
            {
                strncpy(dasnorg, "multicast", ASNORG_LEN);
            }
            else
            {
                dbroadcast = IsBroadcastAddress(flow->destinationIPv4Address);
                if (dbroadcast)
                {
                    strncpy(dasnorg, "broadcast", ASNORG_LEN);
                }
            }
        }

        if (!sprivate_address && !smulticast && !sbroadcast)
        {
            result =
                MMDB_lookup_string(asn_mmdb, sabuf, &gai_error, &mmdb_error);
            if (gai_error)
            {
                fprintf(stderr, "%s: asn getaddrinfo failed: %s", __FUNCTION__, gai_strerror(gai_error));
            }
            else if (mmdb_error)
            {
                fprintf(stderr, "%s: asn geopip lookup failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
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
            }
        }
        else
        {
            strncpy(sasnorg, "private", ASNORG_LEN - 1);
            // Generate a local/private ASN
            if (flow->sourceIPv4Address)
            {
                // ASN 64512 - 65534 is reserved for private use so will generate a synthetic one to enable a histogram that includes private IP mapping
                sasn = 64512 + ((flow->sourceIPv4Address >> 8) % 1024);
                // fprintf(stderr, "sprivate: %u, smulticast: %u, sbroadcast: %u, saddr: %s, sasn hash: %u\n",
                //         sprivate_address, smulticast, sbroadcast, sabuf, sasn);
            }
        }

        if (!dprivate_address && !dmulticast && !dbroadcast)
        {
            result =
                MMDB_lookup_string(asn_mmdb, dabuf, &gai_error, &mmdb_error);
            if (gai_error)
            {
                fprintf(stderr, "%s: asn getaddrinfo failed: %s", __FUNCTION__, gai_strerror(gai_error));
            }
            else if (mmdb_error)
            {
                fprintf(stderr, "%s: asn geopip lookup failed: %s", __FUNCTION__, MMDB_strerror(mmdb_error));
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
            }
        }
        else
        {
            strncpy(dasnorg, "private", ASNORG_LEN - 1);
            // Generate a local/private ASN
            if (flow->destinationIPv4Address)
            {
                // ASN 64512 - 65534 is reserved for private use so will generate a synthetic one to enable a histogram that incluedes private IP mapping
                dasn = 64512 + ((flow->destinationIPv4Address >> 8) % 1024);
                // fprintf(stderr, "dprivate: %u, dmulticast: %u, dbroadcast: %u, daddr: %s, dasn hash: %u\n",
                //         dprivate_address, dmulticast, dbroadcast, dabuf, dasn);
            }
        }
    }
#ifdef COMMENT_OUT
    if (((sasn >= 64512) && (sasn <= 65534)) ||
        ((dasn >= 64512) && (dasn <= 65534)))
    {
        fprintf(stderr, "saddr: %s, sasn hash: %u, daddr: %s, dasn hash: %u\n", sabuf, sasn, dabuf, dasn);
    }
#endif
    duckdb_append_uint32(appender, sasn);
    duckdb_append_uint32(appender, dasn);
    duckdb_append_varchar(appender, sasnorg);
    duckdb_append_varchar(appender, dasnorg);
    duckdb_append_varchar(appender, orientation);
    duckdb_append_null(appender); // label

    //
    // hbos stuff
    //
    duckdb_append_float(appender, 0.0); // hbos_score
    duckdb_append_uint8(appender, 0);   // hbos severity
    duckdb_append_null(appender);       // hbos_map

    //
    // NDPI stuff
    //
    {
        ndpi_protocol protocol;
        protocol.proto.master_protocol = flow->ndpi_master;
        protocol.proto.app_protocol = flow->ndpi_sub;
        protocol.category = 0;
        protocol.protocol_by_ip = 0;
        protocol.custom_category_userdata = NULL;

        g_string_truncate(buffer, 0);
        PrintNDPI(buffer, ndpi_ctx, protocol);
        g_string_truncate(category, 0);
        PrintNDPICategory(category, ndpi_ctx, protocol);
        if (category->len == 3 && category->str[0] == 'v' && category->str[1] == 'p' && category->str[2] == 'n')
        {
            // check category for VPN, if so, prepend it to appid
            g_string_append_printf(buffer, "vpn.");
        }
        duckdb_append_varchar(appender, buffer->str);
        duckdb_append_varchar(appender, category->str);

        //
        // risk stuff
        //
        uint32_t risk_score = 0;
        uint8_t risk_severity = 0;
        if (flow->ndpi_risk > 0)
        {
            u_int16_t cli_score, srv_score;
            risk_score = (uint32_t)ndpi_risk2score(flow->ndpi_risk, &cli_score, &srv_score);
            if (risk_score >= 250)
            {
                // emergency
                risk_severity = 6;
            }
            else if (risk_score >= 200)
            {
                // critical
                risk_severity = 5;
            }
            else if (risk_score >= 150)
            {
                // severe
                risk_severity = 4;
            }
            else if (risk_score >= 100)
            {
                // high
                risk_severity = 3;
            }
            else if (risk_score >= 50)
            {
                // medium
                risk_severity = 2;
            }
            else if (risk_score >= 10)
            {
                // low
                risk_severity = 1;
            }
            else
            {
                risk_severity = 0;
            }
        }
        duckdb_append_uint32(appender, flow->ndpi_risk); // risk bits
        duckdb_append_uint32(appender, risk_score);      // risk score
        duckdb_append_uint8(appender, risk_severity);    // risk severity
        duckdb_append_null(appender);                    // risk label
    }

    duckdb_append_uint8(appender, 0); // trigger

    // --- Free all GString buffers on all return paths ---
    /* release scratch buffers */
    g_string_free(category, 1);
    g_string_free(buffer, 1);

    return 0;
}

static int WriteIpfixRecord(const char *observation,
                            duckdb_appender appender,
                            struct ndpi_detection_module_struct *ndpi_ctx,
                            const YAF_FLOW_RECORD *flow,
                            MMDB_s *asn_mmdb,
                            MMDB_s *country_mmdb,
                            uint16_t risk_threshold)
{
    if ((flow->protocolIdentifier == 0) && (flow->destinationIPv4Address == 0))
    {
        // skip IPv6 Hop-by-Hop Option
        return 0;
    }

    if (AppendIpfixRecord(appender, observation, ndpi_ctx, flow, asn_mmdb, country_mmdb, risk_threshold) < 0)
    {
        fprintf(stderr, "%s: AppendIpfixRecord error\n", __FUNCTION__);
        return -1;
    }

    if (duckdb_appender_end_row(appender) == DuckDBError)
    {
        fprintf(stderr, "%s: %s\n", __FUNCTION__, duckdb_appender_error(appender));
        return -1;
    }
    return 1;
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
    // fprintf(stderr, "%s\n", __FUNCTION__);
    do
    {
        GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;
        if (!gnat)
            break;

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
    fprintf(stderr, "%s\n", __FUNCTION__);
    gboolean status = FALSE;
    char file_name[PATH_MAX + 1];
    char tmp_file[(PATH_MAX * 2) + 1];
    char parquet_file[(PATH_MAX * 2) + 1];
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
        if (strlen(gnat->output_dir))
        {
            fprintf(stderr, "%s: missing output specifier\n", __FUNCTION__);
            break;
        }

        if (duckdb_appender_flush(gnat->appender) == DuckDBError)
        {
            fprintf(stderr, "%s: %s\n", __FUNCTION__, duckdb_appender_error(gnat->appender));
        }
        if (duckdb_appender_destroy(&gnat->appender) == DuckDBError)
        {
            fprintf(stderr, "%s: %s\n", __FUNCTION__, duckdb_appender_error(gnat->appender));
        }

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
    char tmp_file[(PATH_MAX * 3) + 1];
    char parquet_file[(PATH_MAX * 4) + 1];
    char parquet_export_command[(PATH_MAX * 5) + 1];
    do
    {
        GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;
        if (!gnat)
            break;

        //
        if (duckdb_appender_flush(gnat->appender) == DuckDBError)
        {
            fprintf(stderr, "%s: %s\n", __FUNCTION__, duckdb_appender_error(gnat->appender));
        }
        if (duckdb_appender_destroy(&gnat->appender) == DuckDBError)
        {
            fprintf(stderr, "%s: %s\n", __FUNCTION__, duckdb_appender_error(gnat->appender));
        }
        //
        // bulk update flow id (using duckdb default uuid() generator)
        //
        duckdb_result db_result;
        if (duckdb_query(gnat->con, FLOW_GENERATE_UUID, &db_result) == DuckDBError)
        {
            fprintf(stderr, "%s: failed to generate uuids: \n%s\n", __FUNCTION__, duckdb_result_error(&db_result));
            break;
        }

        if (strlen(gnat->output_dir))
        {
            char buffer[128];
            char rfc339_name[256];
            struct timeval tv;
            gettimeofday(&tv, NULL);

            struct tm *timeinfo = gmtime(&tv.tv_sec);
            strftime(buffer, 80, "%Y-%m-%dT%H:%M:%S", timeinfo);
            snprintf(rfc339_name, sizeof(rfc339_name) - 1, "%s-%s.%06ld+00:00", gnat->observation, buffer, tv.tv_usec);

            snprintf(tmp_file, sizeof(tmp_file) - 1, "%s/.%s", gnat->output_dir, rfc339_name);
            snprintf(parquet_file, sizeof(parquet_file) - 1, "%s/%s.parquet", gnat->output_dir, rfc339_name);

            snprintf(parquet_export_command, sizeof(parquet_export_command) - 1,
                     " COPY (SELECT * FROM flow) TO '%s' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);", tmp_file);
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

        // if (gnat->ipfix_flows > 0)
        //     printf("%s: records [%lu]\n", __FUNCTION__, gnat->ipfix_flows);
        // else
        //     printf("%s: error [%lu]\n", __FUNCTION__, gnat->ipfix_flows);

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
    YAF_FLOW_RECORD ipfix_record;
    size_t yaf_rec_len = sizeof(ipfix_record);
    while (fBufNext(gnat->input_buf, (uint8_t *)&ipfix_record, &yaf_rec_len, err))
    {
        int status = WriteIpfixRecord(gnat->observation,
                                      gnat->appender,
                                      gnat->ndpi_ctx,
                                      &ipfix_record,
                                      gnat->asn_mmdb_ptr,
                                      gnat->country_mmdb_ptr,
                                      gnat->risk_threshold);
        if (status < 0)
        {
            fprintf(stderr, "%s: error\n", __FUNCTION__);
            gnat->ipfix_flows = -1;
            sink->active = FALSE;
            *flags |= (MIO_F_CTL_SINKCLOSE | MIO_F_CTL_ERROR);
            return FALSE;
        }
        else if (status > 0)
        {
            ++gnat->ipfix_flows;
        }
        else
        {
            ++gnat->ipfix_flows_skipped;
        }
        memset(&ipfix_record, 0, yaf_rec_len);
    }

    if (g_error_matches(*err, FB_ERROR_DOMAIN,FB_ERROR_EOF))
    {
        /* EOF on a single collector not an issue. */
        *flags |= (MIO_F_CTL_SINKCLOSE | MIO_F_CTL_TERMINATE);
        g_clear_error(err);
        return TRUE;
    }

    if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX))
    {
        /*  
            A message was received larger than the collector buffer size.
            Usually when YAF is stopped adbruptly, the collector
            will receive a message that is larger than the buffer size.

            Just skip the file and continue processing the next one.
         */
        *flags |= (MIO_F_CTL_SINKCLOSE | MIO_F_CTL_TERMINATE);
        g_clear_error(err);
        return TRUE;
    }

    //printf(stderr, "%s: invalid format\n", __FUNCTION__);
    /* bad message */
    sink->active = FALSE;
    *flags |= (MIO_F_CTL_SINKCLOSE | MIO_F_CTL_TERMINATE | MIO_F_CTL_ERROR);
    return FALSE;
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
                             &gnat->country_mmdb,
                             gnat->risk_threshold) < 0)

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
