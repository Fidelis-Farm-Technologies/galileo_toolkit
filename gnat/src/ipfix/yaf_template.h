/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

/*
 * To ensure interoperability the model was derived from 
 * the YAF project: ${YAF_PROJECT_DIR}/infomodel/cert.i
 */

/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
#pragma once

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>


#include <fixbuf/public.h>

#include <airframe/mio.h>
#include <airframe/mio_config.h>
#include <airframe/mio_sink_file.h>

#include <airframe/logconfig.h>
#include <airframe/daeconfig.h>
#include <airframe/airutil.h>
#include <airframe/privconfig.h>
#include <airframe/airlock.h>

#include <yaf/yafcore.h>
#include <yaf/autoinc.h>
#include <yaf/yaftab.h>
#include <yaf/yafrag.h>
#include <yaf/decode.h>
#include <yaf/ring.h>
#include <yaf/decode.h>

#define FB_IE_INIT_FULL(_name_, _ent_, _num_, _len_, _flags_, \
                        _min_, _max_, _type_, _desc_)         \
    { _ent_, _num_, _len_, _flags_, _type_, _min_, _max_, _name_, _desc_ }

#define COLLECTOR_CONTEXT_INIT                                     \
    {NULL, NULL, 0, NULL, NULL, NULL, NULL, 0, AIR_LOCK_INIT, \
     NULL, 0, 0, NULL, NULL, 0, AIR_LOCK_INIT}


#define FLAG_GEN(h, v) (((h) & 0xFFFF) << 16 | ((v) & 0xFFFF))

#define YAF_FLOW_FULL_TID   0xB800 /* base no internal*/
#define YAF_PROCESS_STATS_TID   0xD003

#define YTF_RLE         FLAG_GEN(0x0001, 0x0000)
#define YTF_FLE         FLAG_GEN(0x0000, 0x0001) 
#define YTF_TCP         FLAG_GEN(0x0000, 0x0002)
#define YTF_MPTCP       FLAG_GEN(0x0000, 0x0004)
#define YTF_IP4         FLAG_GEN(0x0002, 0x0000)
#define YTF_IP6         FLAG_GEN(0x0000, 0x0008)
#define YTF_TOTAL       FLAG_GEN(0x0004, 0x0000)                                                   
#define YTF_DELTA       FLAG_GEN(0x0000, 0x0010)
#define YTF_BIF         FLAG_GEN(0x0000, 0x0020) 
#define YTF_DAGIF       FLAG_GEN(0x0000, 0x0040)
#define YTF_STATS       FLAG_GEN(0x0000, 0x0080)
#define YTF_MAC         FLAG_GEN(0x0000, 0x0100)
#define YTF_ENTROPY     FLAG_GEN(0x0000, 0x0200)
#define YTF_VNI         FLAG_GEN(0x0000, 0x0400)
#define YTF_NDPI        FLAG_GEN(0x0010, 0x0000)
#define YTF_MPLS        FLAG_GEN(0x0100, 0x0000) 
#define YTF_INTERNAL    FLAG_GEN(0x0000, 0x0800)
#define YTF_ALL         FLAG_GEN(0xFFFE, 0x0FFF)                                           

/**
 * GError domain for YAF errors. All YAF errors belong to this domain.
 * In addition, YAF core library routines can return libfixbuf errors if
 * reading or writing fails.
 */
#define YAF_ERROR_DOMAIN        (g_quark_from_string("certYAFError"))
/** A YAF file header was malformed. The file is probably not a YAF file. */
#define YAF_ERROR_HEADER        1
/** Illegal argument error. */
#define YAF_ERROR_ARGUMENT      2
/** General I/O error */
#define YAF_ERROR_IO            3
/** YAF could not accept IPFIX input due to missing fields. */
#define YAF_ERROR_IPFIX         4
/** Requested feature is not available */
#define YAF_ERROR_IMPL          5
/** Internal error occured (aka a bug)*/
#define YAF_ERROR_INTERNAL      6
/** Hard program limit reached */
#define YAF_ERROR_LIMIT         7
/** End of file */
#define YAF_ERROR_EOF           8
/** Internal alignment error */
#define YAF_ERROR_ALIGNMENT         9
/** Packet payload processing error */
#define YAF_ERROR_PACKET_PAYLOAD    10

static fbInfoElement_t g_yaf_enterprise_elements[] = {
    FB_IE_INIT_FULL("obsoleteReverseOctetTotalCount", 6871, 12, 8, FB_IE_TOTALCOUNTER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_64, NULL),
    FB_IE_INIT_FULL("obsoleteReversePacketTotalCount", 6871, 13, 8, FB_IE_TOTALCOUNTER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_64, NULL),
    FB_IE_INIT_FULL("initialTCPFlags", 6871, 14, 2, FB_IE_FLAGS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("unionTCPFlags", 6871, 15, 2, FB_IE_FLAGS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("obsoleteReverseInitialTCPFlags", 6871, 16, 1, FB_IE_FLAGS, 0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("obsoleteReverseUnionTCPFlags", 6871, 17, 1, FB_IE_FLAGS, 0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("payload", 6871, 18, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE, 0, 0, FB_OCTET_ARRAY, NULL),
    FB_IE_INIT_FULL("obsoleteReversePayload", 6871, 19, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_OCTET_ARRAY, NULL),
    FB_IE_INIT_FULL("obsoleteReverseTcpSequenceNumber", 6871, 20, 4, FB_IE_QUANTITY | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("reverseFlowDeltaMilliseconds", 6871, 21, 4, FB_IE_QUANTITY | FB_UNITS_MILLISECONDS | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("obsoleteReverseVlanId", 6871, 29, 2, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("silkFlowtypeId", 6871, 30, 1, FB_IE_IDENTIFIER, 0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("silkSensorId", 6871, 31, 2, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("silkTCPState", 6871, 32, 1, FB_IE_FLAGS, 0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("silkAppLabel", 6871, 33, 2, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("payloadEntropy", 6871, 35, 1, FB_IE_QUANTITY | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("osName", 6871, 36, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("osVersion", 6871, 37, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("firstPacketBanner", 6871, 38, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE, 0, 0, FB_OCTET_ARRAY, NULL),
    FB_IE_INIT_FULL("secondPacketBanner", 6871, 39, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE, 0, 0, FB_OCTET_ARRAY, NULL),
    FB_IE_INIT_FULL("flowAttributes", 6871, 40, 2, FB_IE_FLAGS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("yafExpiredFragmentCount", 6871, 100, 4, FB_IE_TOTALCOUNTER | FB_UNITS_PACKETS | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("yafAssembledFragmentCount", 6871, 101, 4, FB_IE_TOTALCOUNTER | FB_UNITS_PACKETS | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("yafMeanFlowRate", 6871, 102, 4, FB_IE_QUANTITY | FB_UNITS_FLOWS | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("yafMeanPacketRate", 6871, 103, 4, FB_IE_QUANTITY | FB_UNITS_PACKETS | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("yafFlowTableFlushEventCount", 6871, 104, 4, FB_IE_TOTALCOUNTER | FB_UNITS_FLOWS | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("yafFlowTablePeakCount", 6871, 105, 4, FB_IE_QUANTITY | FB_UNITS_FLOWS | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("yafFlowKeyHash", 6871, 106, 4, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("osFingerprint", 6871, 107, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("mptcpInitialDataSequenceNumber", 6871, 289, 8, FB_IE_QUANTITY | FB_IE_F_ENDIAN, 0, 0, FB_UINT_64, NULL),
    FB_IE_INIT_FULL("mptcpReceiverToken", 6871, 290, 4, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("mptcpMaximumSegmentSize", 6871, 291, 2, FB_IE_QUANTITY | FB_IE_F_ENDIAN, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("mptcpAddressId", 6871, 292, 1, FB_IE_IDENTIFIER, 0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("mptcpFlags", 6871, 293, 1, FB_IE_FLAGS, 0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("sslCertificateSHA1", 6871, 298, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_OCTET_ARRAY, NULL),
    FB_IE_INIT_FULL("sslCertificateMD5", 6871, 299, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_OCTET_ARRAY, NULL),
    FB_IE_INIT_FULL("ndpiL7Protocol", 6871, 300, 2, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("ndpiL7SubProtocol", 6871, 301, 2, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("ndpiRisk", 6871, 602, 8, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_64, NULL),    
    FB_IE_INIT_FULL("pipelineDNSARecord", 6871, 305, FB_IE_VARLEN, FB_IE_LIST, 0, 0, FB_SUB_TMPL_LIST, NULL),
    FB_IE_INIT_FULL("pipelineDNSAAAARecord", 6871, 306, FB_IE_VARLEN, FB_IE_LIST, 0, 0, FB_SUB_TMPL_LIST, NULL),
    FB_IE_INIT_FULL("pipelineDNSResourceRecord", 6871, 307, FB_IE_VARLEN, FB_IE_LIST, 0, 0, FB_SUB_TMPL_LIST, NULL),
    FB_IE_INIT_FULL("sslCertValidityTotalDays", 6871, 460, 4, FB_IE_QUANTITY | FB_IE_F_ENDIAN, 0, 0, FB_INT_32, NULL),
    FB_IE_INIT_FULL("sslCertValidityDaysTimeOfUse", 6871, 461, 4, FB_IE_QUANTITY | FB_IE_F_ENDIAN, 0, 0, FB_INT_32, NULL),
    FB_IE_INIT_FULL("sslCertificateSHA256", 6871, 462, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_OCTET_ARRAY, NULL),
    FB_IE_INIT_FULL("smallPacketCount", 6871, 500, 4, FB_IE_TOTALCOUNTER | FB_UNITS_PACKETS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("nonEmptyPacketCount", 6871, 501, 4, FB_IE_TOTALCOUNTER | FB_UNITS_PACKETS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("dataByteCount", 6871, 502, 8, FB_IE_TOTALCOUNTER | FB_UNITS_OCTETS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_64, NULL),
    FB_IE_INIT_FULL("averageInterarrivalTime", 6871, 503, 8, FB_IE_QUANTITY | FB_UNITS_MILLISECONDS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_64, NULL),
    FB_IE_INIT_FULL("standardDeviationInterarrivalTime", 6871, 504, 8, FB_IE_QUANTITY | FB_UNITS_MILLISECONDS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_64, NULL),
    FB_IE_INIT_FULL("firstNonEmptyPacketSize", 6871, 505, 2, FB_IE_QUANTITY | FB_UNITS_OCTETS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("maxPacketSize", 6871, 506, 2, FB_IE_QUANTITY | FB_UNITS_OCTETS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("firstEightNonEmptyPacketDirections", 6871, 507, 1, FB_IE_FLAGS | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("standardDeviationPayloadLength", 6871, 508, 2, FB_IE_QUANTITY | FB_UNITS_OCTETS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("tcpUrgentCount", 6871, 509, 4, FB_IE_TOTALCOUNTER | FB_UNITS_PACKETS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("largePacketCount", 6871, 510, 4, FB_IE_TOTALCOUNTER | FB_UNITS_PACKETS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("certToolTombstoneId", 6871, 550, 4, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("certToolExporterConfiguredId", 6871, 551, 2, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("certToolExporterUniqueId", 6871, 552, 2, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("certToolId", 6871, 553, 4, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 1, 6, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("certToolTombstoneAccessList", 6871, 554, FB_IE_VARLEN, FB_IE_LIST, 0, 0, FB_SUB_TMPL_LIST, NULL),
    FB_IE_INIT_FULL("smDNSData", 6871, 927, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("dnsHitCount", 6871, 928, 2, FB_IE_QUANTITY | FB_IE_F_ENDIAN, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("smDedupHitCount", 6871, 929, 8, FB_IE_TOTALCOUNTER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_64, NULL),
    FB_IE_INIT_FULL("smDedupData", 6871, 930, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_OCTET_ARRAY, NULL),
    FB_IE_INIT_FULL("smIPSetMatchesSource", 6871, 931, 1, FB_IE_FLAGS, 0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("smIPSetMatchesDestination", 6871, 932, 1, FB_IE_FLAGS, 0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("smIPSetName", 6871, 933, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("smPrefixMapLabelSource", 6871, 934, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("smPrefixMapLabelDestination", 6871, 935, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("smPrefixMapTypeId", 6871, 936, 1, FB_IE_IDENTIFIER, 0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("smPrefixMapName", 6871, 937, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("silkFlowtypeName", 6871, 938, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("silkClassName", 6871, 939, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("silkTypeName", 6871, 940, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("silkSensorName", 6871, 941, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("silkSensorDescription", 6871, 942, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("yafLayer2SegmentId", 6871, 943, 4, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
    FB_IE_INIT_FULL("templateName", 6871, 1000, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("templateDescription", 6871, 1001, FB_IE_VARLEN, FB_IE_DEFAULT, 0, 0, FB_STRING, NULL),

    FB_IE_NULL
};



/* IPFIX definition of the full YAF flow record */
static fbInfoElementSpec_t g_yaf_flow_spec[] = {
    /* Millisecond start and end (epoch) (native time) */
    /* used by SM to label templates as TC_FLOW */
    { "flowStartMilliseconds",              8, 0 },
    /* used by SM to label templates as TC_FLOW */
    { "flowEndMilliseconds",                8, 0 },
    /* Counters */
    { "octetTotalCount",                    8, YTF_FLE | YTF_TOTAL },
    { "reverseOctetTotalCount",             8, YTF_FLE | YTF_TOTAL | YTF_BIF },
    { "packetTotalCount",                   8, YTF_FLE | YTF_TOTAL },
    { "reversePacketTotalCount",            8, YTF_FLE | YTF_TOTAL | YTF_BIF },
    /* delta Counters */
    { "octetDeltaCount",                    8, YTF_FLE | YTF_DELTA },
    { "reverseOctetDeltaCount",             8, YTF_FLE | YTF_DELTA | YTF_BIF },
    { "packetDeltaCount",                   8, YTF_FLE | YTF_DELTA },
    { "reversePacketDeltaCount",            8, YTF_FLE | YTF_DELTA | YTF_BIF },
    /* Reduced-length counters */
    { "octetTotalCount",                    4, YTF_RLE | YTF_TOTAL },
    { "reverseOctetTotalCount",             4, YTF_RLE | YTF_TOTAL | YTF_BIF },
    { "packetTotalCount",                   4, YTF_RLE | YTF_TOTAL },
    { "reversePacketTotalCount",            4, YTF_RLE | YTF_TOTAL | YTF_BIF },
    /* Reduced-length delta counters */
    { "octetDeltaCount",                    4, YTF_RLE | YTF_DELTA },
    { "reverseOctetDeltaCount",             4, YTF_RLE | YTF_DELTA | YTF_BIF },
    { "packetDeltaCount",                   4, YTF_RLE | YTF_DELTA },
    { "reversePacketDeltaCount",            4, YTF_RLE | YTF_DELTA | YTF_BIF },
    /* 5-tuple and flow status */
    { "sourceIPv6Address",                  16, YTF_IP6 },
    { "destinationIPv6Address",             16, YTF_IP6 },
    { "sourceIPv4Address",                  4, YTF_IP4 },
    { "destinationIPv4Address",             4, YTF_IP4 },
    /* used by SM to label templates as TC_FLOW */
    { "sourceTransportPort",                2, 0 },
    /* used by SM to label templates as TC_FLOW */
    { "destinationTransportPort",           2, 0 },
    /* used by SM to label templates as TC_FLOW */
    { "flowAttributes",                     2, 0 },
    /* used by SM to label flows as reverse */
    { "reverseFlowAttributes",              2, YTF_BIF },
    /* used by SM to label templates as TC_FLOW */
    { "protocolIdentifier",                 1, 0 },
    /* used by SM to label templates as TC_FLOW */
    { "flowEndReason",                      1, 0 },
    { "paddingOctets",                      2, YTF_INTERNAL },

    /* Round-trip time */
    /* used by SM to label flows as reverse */
    { "reverseFlowDeltaMilliseconds",       4, YTF_BIF }, /*  32-bit */
    /* used by SM to label templates as TC_FLOW */
    { "vlanId",                             2, 0 },
    /* used by SM to label flows as reverse */
    { "reverseVlanId",                      2, YTF_BIF },
    /* used by SM to label templates as TC_FLOW */
    { "ipClassOfService",                   1, 0 },
    /* used by SM to label flows as reverse */
    { "reverseIpClassOfService",            1, YTF_BIF },

    /* Entropy */
    { "payloadEntropy",                     1, YTF_ENTROPY },
    { "reversePayloadEntropy",              1, YTF_ENTROPY | YTF_BIF },

    /* MPTCP */
    { "mptcpInitialDataSequenceNumber",     8, YTF_MPTCP },
    { "mptcpReceiverToken",                 4, YTF_MPTCP },
    { "mptcpMaximumSegmentSize",            2, YTF_MPTCP },
    { "mptcpAddressId",                     1, YTF_MPTCP },
    { "mptcpFlags",                         1, YTF_MPTCP },

    /* MAC */
    { "paddingOctets",                      2, YTF_INTERNAL },
    { "sourceMacAddress",                   6, YTF_MAC },
    { "destinationMacAddress",              6, YTF_MAC },
    { "paddingOctets",                      2, YTF_INTERNAL },

    /* DAG */
    { "ingressInterface",                   4, YTF_DAGIF },
    { "egressInterface",                    4, YTF_DAGIF },

    /* VNI */
    { "yafLayer2SegmentId",                 4, YTF_VNI },
    { "paddingOctets",                      4, YTF_INTERNAL },

    /* Flow stats */
    { "dataByteCount",                      8, YTF_STATS },
    { "averageInterarrivalTime",            8, YTF_STATS },
    { "standardDeviationInterarrivalTime",  8, YTF_STATS },
    { "tcpUrgTotalCount",                   4, YTF_STATS },
    { "smallPacketCount",                   4, YTF_STATS },
    { "nonEmptyPacketCount",                4, YTF_STATS },
    { "largePacketCount",                   4, YTF_STATS },
    { "firstNonEmptyPacketSize",            2, YTF_STATS },
    { "maxPacketSize",                      2, YTF_STATS },
    { "standardDeviationPayloadLength",     2, YTF_STATS },
    { "firstEightNonEmptyPacketDirections", 1, YTF_STATS },
    { "paddingOctets",                      1, YTF_STATS | YTF_INTERNAL },
    { "reverseDataByteCount",               8, YTF_STATS | YTF_BIF },
    { "reverseAverageInterarrivalTime",     8, YTF_STATS | YTF_BIF },
    { "reverseStandardDeviationInterarrivalTime", 8, YTF_STATS | YTF_BIF },
    { "reverseTcpUrgTotalCount",            4, YTF_STATS | YTF_BIF },
    { "reverseSmallPacketCount",            4, YTF_STATS | YTF_BIF },
    { "reverseNonEmptyPacketCount",         4, YTF_STATS | YTF_BIF },
    { "reverseLargePacketCount",            4, YTF_STATS | YTF_BIF },
    { "reverseFirstNonEmptyPacketSize",     2, YTF_STATS | YTF_BIF },
    { "reverseMaxPacketSize",               2, YTF_STATS | YTF_BIF },
    { "reverseStandardDeviationPayloadLength", 2, YTF_STATS | YTF_BIF },

    /* TCP */
    { "initialTCPFlags",                    1, YTF_TCP },
    { "unionTCPFlags",                      1, YTF_TCP },
    { "tcpSequenceNumber",                  4, YTF_TCP },
    { "reverseTcpSequenceNumber",           4, YTF_TCP | YTF_BIF },
    { "reverseInitialTCPFlags",             1, YTF_TCP | YTF_BIF },
    { "reverseUnionTCPFlags",               1, YTF_TCP | YTF_BIF },

    { "paddingOctets",                      2, YTF_INTERNAL },
    { "ndpiL7Protocol",                     2, YTF_NDPI },
    { "ndpiL7SubProtocol",                  2, YTF_NDPI },
    { "ndpiRisk",                           8, YTF_NDPI },

    /* MPLS */
    { "paddingOctets",                      1, YTF_INTERNAL },
    { "mplsTopLabelStackSection",           3, YTF_MPLS },
    { "mplsLabelStackSection2",             3, YTF_MPLS },
    { "mplsLabelStackSection3",             3, YTF_MPLS },

    FB_IESPEC_NULL
};


// for future use
static fbInfoElementSpec_t yaf_process_stats_spec[] = {
    { "observationDomainId",                4, 0 },
    { "exportingProcessId",                 4, 0 },
    { "exporterIPv4Address",                4, 0 },
    { "observationTimeSeconds",             4, 0 },
    { "systemInitTimeMilliseconds",         8, 0 },
    { "exportedFlowRecordTotalCount",       8, 0 },
    { "packetTotalCount",                   8, 0 },
    { "droppedPacketTotalCount",            8, 0 },
    { "ignoredPacketTotalCount",            8, 0 },
    { "notSentPacketTotalCount",            8, 0 },
    { "yafExpiredFragmentCount",            4, 0 },
    { "yafAssembledFragmentCount",          4, 0 },
    { "yafFlowTableFlushEventCount",        4, 0 },
    { "yafFlowTablePeakCount",              4, 0 },
    { "yafMeanFlowRate",                    4, 0 },
    { "yafMeanPacketRate",                  4, 0 },
    FB_IESPEC_NULL
};

#if defined(COMMENT_OUT)

typedef struct yfConfig_st {
    char              *inspec;
    char              *livetype;
    char              *outspec;
    char              *bpf_expr;
    char              *pcapdir;
    gboolean           pcap_per_flow;
    gboolean           lockmode;
    gboolean           ipfixNetTrans;
    gboolean           noerror;
    gboolean           exportInterface;
    gboolean           macmode;
    gboolean           silkmode;
    gboolean           nostats;
    gboolean           statsmode;
    gboolean           deltaMode;
    gboolean           mpls_mode;
    gboolean           no_output;
    gboolean           tmpl_metadata;
    gboolean           ie_metadata;
    gboolean           no_tombstone;
    gboolean           p0fPrinterMode;
    gboolean           fpExportMode;
    gboolean           layer2IdExportMode;
    uint16_t           tombstone_configured_id;
    uint32_t           ingressInt;
    uint32_t           egressInt;
    uint64_t           stats;
    uint64_t           rotate_ms;
    /* in seconds - convert to ms in yaf.c */
    uint64_t           yaf_udp_template_timeout;
    uint64_t           max_pcap;
    uint64_t           pcap_timer;
    uint32_t           odid;
    fbConnSpec_t       connspec;
} yfConfig_t;

#define YF_CONFIG_INIT                                       \
    {NULL, NULL, NULL, NULL, NULL, FALSE, FALSE, FALSE,      \
     FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, \
     FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, 0,     \
     0, 0, 0, 0, 0, 5, 0, 0, FB_CONNSPEC_INIT}

typedef struct yfContext_st {
    /** Configuration */
    yfConfig_t     *cfg;
    /** Packet source */
    void           *pktsrc;
    /** Packet ring buffer */
    size_t          pbuflen;
    rgaRing_t      *pbufring;
    /** Decoder */
    yfDecodeCtx_t  *dectx;
    /** Flow table */
    yfFlowTab_t    *flowtab;
    /** Fragment table */
    yfFragTab_t    *fragtab;
    /** Output rotation state */
    uint64_t        last_rotate_ms;
    /** Output lock buffer */
    AirLock         lockbuf;
    /** Output IPFIX buffer */
    fBuf_t         *fbuf;
    /** UDP last template send time (in ms) */
    uint64_t        lastUdpTempTime;
    /** yaf start time */
    uint64_t        yaf_start_time;
    /** Error description */
    GError         *err;
    /** Pcap File Ptr for Rolling Pcap*/
    pcap_dumper_t  *pcap;
    /** Pcap Offset into Rolling Pcap */
    uint64_t        pcap_offset;
    /** Pcap Lock Buffer */
    AirLock         pcap_lock;
} yfContext_t;


#endif
