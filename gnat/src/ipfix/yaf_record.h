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
#include <ctype.h>

#include <fixbuf/public.h>

typedef struct _YAF_FLOW_RECORD_
{
    uint64_t flowStartMilliseconds;
    uint64_t flowEndMilliseconds;

    uint64_t octetTotalCount;
    uint64_t reverseOctetTotalCount;
    uint64_t packetTotalCount;
    uint64_t reversePacketTotalCount;

    uint64_t octetDeltaCount;
    uint64_t reverseOctetDeltaCount;
    uint64_t packetDeltaCount;
    uint64_t reversePacketDeltaCount;

    uint8_t sourceIPv6Address[16];
    uint8_t destinationIPv6Address[16];
    uint32_t sourceIPv4Address;
    uint32_t destinationIPv4Address;
    uint16_t sourceTransportPort;
    uint16_t destinationTransportPort;
    uint16_t flowAttributes;
    uint16_t reverseFlowAttributes;
    uint8_t protocolIdentifier;
    uint8_t flowEndReason;

    uint8_t paddingOctets1[2];

    int32_t reverseFlowDeltaMilliseconds;
    uint16_t vlanId;
    uint16_t reverseVlanId;
    uint8_t ipClassOfService;
    uint8_t reverseIpClassOfService;

    uint8_t entropy;
    uint8_t reverseEntropy;

    /* MPTCP */
    uint64_t mptcpInitialDataSequenceNumber;
    uint32_t mptcpReceiverToken;
    uint16_t mptcpMaximumSegmentSize;
    uint8_t mptcpAddressId;
    uint8_t mptcpFlags;

    /* MAC */
    uint8_t paddingOctets3[2];
    uint8_t sourceMacAddress[6];
    uint8_t destinationMacAddress[6];
    uint8_t paddingOctets3_2[2];

    /* DAG */
    uint32_t ingressInterface;
    uint32_t egressInterface;

    uint32_t yafLayer2SegmentId;
    uint8_t paddingOctets4[4];

    /* Flow stats */
    uint64_t dataByteCount;
    uint64_t averageInterarrivalTime;
    uint64_t standardDeviationInterarrivalTime;
    uint32_t tcpUrgTotalCount;
    uint32_t smallPacketCount;
    uint32_t nonEmptyPacketCount;
    uint32_t largePacketCount;
    uint16_t firstNonEmptyPacketSize;
    uint16_t maxPacketSize;
    uint16_t standardDeviationPayloadLength;
    uint8_t firstEightNonEmptyPacketDirections;
    uint8_t paddingOctets5[1];
    /* reverse flow stats */
    uint64_t reverseDataByteCount;
    uint64_t reverseAverageInterarrivalTime;
    uint64_t reverseStandardDeviationInterarrivalTime;
    uint32_t reverseTcpUrgTotalCount;
    uint32_t reverseSmallPacketCount;
    uint32_t reverseNonEmptyPacketCount;
    uint32_t reverseLargePacketCount;
    uint16_t reverseFirstNonEmptyPacketSize;
    uint16_t reverseMaxPacketSize;
    uint16_t reverseStandardDeviationPayloadLength;

    /* TCP */
    uint8_t initialTCPFlags;
    uint8_t unionTCPFlags;
    uint32_t tcpSequenceNumber;
    uint32_t reverseTcpSequenceNumber;
    uint8_t reverseInitialTCPFlags;
    uint8_t reverseUnionTCPFlags;

    /* NDPI */
    uint8_t paddingOctets8[2];
    uint16_t ndpi_master;
    uint16_t ndpi_sub;
    uint64_t ndpi_risk;

    /* MPLS */
    uint8_t paddingOctets7[1];
    uint8_t mpls_label1[3];
    uint8_t mpls_label2[3];
    uint8_t mpls_label3[3];

    fbSubTemplateMultiList_t subTemplateMultiList;

} YAF_FLOW_RECORD;

typedef struct _YAF_STATS_RECORD_
{
    uint32_t   observationDomainId;
    uint32_t   exportingProcessId;
    uint32_t   exporterIPv4Address;
    uint32_t   observationTimeSeconds;
    uint64_t   systemInitTimeMilliseconds;
    uint64_t   exportedFlowTotalCount;
    uint64_t   packetTotalCount;
    uint64_t   droppedPacketTotalCount;
    uint64_t   ignoredPacketTotalCount;
    uint64_t   notSentPacketTotalCount;
    uint32_t   yafExpiredFragmentCount;
    uint32_t   yafAssembledFragmentCount;
    uint32_t   flowTableFlushEvents;
    uint32_t   yafFlowTablePeakCount;
    uint32_t   yafMeanFlowRate;
    uint32_t   yafMeanPacketRate;
} YAF_STATS_RECORD;
