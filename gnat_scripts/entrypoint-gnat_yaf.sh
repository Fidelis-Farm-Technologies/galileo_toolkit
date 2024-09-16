#!/bin/bash

if [ ! -d  "/var/spool" ]; then
    mkdir /var/spool
fi

if [ ! -d  "/var/spool/${GNAT_OBSERVATION_TAG}" ]; then
    mkdir /var/spool/${GNAT_OBSERVATION_TAG}
fi

if [ ! -z "${GNAT_PCAP_LIST}" ]; then
    GNAT_INPUT="--in ${GNAT_PCAP_LIST} --caplist"
    echo "pcap offline: ${GNAT_INPUT}"
elif [ ! -z "${GNAT_INTERFACE}" ]; then
    GNAT_INPUT="--in ${GNAT_INTERFACE} --live=pcap"
     echo "pcap live: ${GNAT_INPUT}"
else
    echo "Missing environment variable GNAT_INTERFACE or GNAT_PCAP_LIST"
    exit 1
fi

if [ -z "${GNAT_EXPORT_INTERVAL}" ]; then
    GNAT_EXPORT_INTERVAL=15
fi

if [ -z "${GNAT_OPTIONS}" ]; then
    GNAT_OPTIONS="--entropy --ndpi --verbose --max-payload=2048 --flow-stats --mac --active-timeout 300 --idle-timeout 120 --out /var/spool/${GNAT_OBSERVATION_TAG}/${GNAT_OBSERVATION_TAG} --lock"
fi

export LTDL_LIBRARY_PATH=/opt/gnat/lib/yaf

if [ ! -z "${GNAT_PCAP_LIST}" ]; then
    /opt/gnat/bin/gnat_yaf ${GNAT_INPUT} ${GNAT_OPTIONS}

    echo "finished processing pcap list: ${GNAT_PCAP_LIST}"
    # if in pcap procesing mode, then sleep until the service is explicity shut down
    while true
    do
        sleep 1
    done
else
    /opt/gnat/bin/gnat_yaf ${GNAT_INPUT} ${GNAT_OPTIONS} --rotate ${GNAT_EXPORT_INTERVAL} 
fi
