#!/bin/bash

if [ -z "${GNAT_OUTPUT_DIR}" ]; then
    GNAT_OUTPUT_DIR=/var/spool/${GNAT_OBSERVATION_TAG}
fi

if [ ! -d  "${GNAT_OUTPUT_DIR}" ]; then
    mkdir -p ${GNAT_OUTPUT_DIR}
fi

for file in ${GNAT_OUTPUT_DIR}/*.lock; do
  if [ -f "$file" ]; then
    echo "removing $file"
    rm $file
  fi
done

if [ ! -z "${GNAT_PCAP_LIST}" ]; then
    GNAT_INPUT_SPEC="--in ${GNAT_PCAP_LIST} --caplist"
    echo "pcap offline: ${GNAT_INPUT_SPEC}"
elif [ ! -z "${GNAT_INTERFACE}" ]; then
    GNAT_INPUT_SPEC="--in ${GNAT_INTERFACE} --live=pcap"
     echo "pcap live: ${GNAT_INPUT_SPEC}"
else
    echo "Missing environment variable GNAT_INTERFACE or GNAT_PCAP_LIST"
    exit 1
fi

if [ -z "${GNAT_EXPORT_INTERVAL}" ]; then
    GNAT_EXPORT_INTERVAL=20
fi

if [ -z "${GNAT_OPTIONS}" ]; then
    GNAT_OPTIONS="--entropy --ndpi --verbose  --mac --max-payload=4096 --flow-stats --no-template-metadata --no-element-metadata --no-tombstone --active-timeout 180 --idle-timeout 60 --out ${GNAT_OUTPUT_DIR}/${GNAT_OBSERVATION_TAG} --lock"
    # GNAT_OPTIONS="--entropy --ndpi --verbose --max-payload=2048 --flow-stats --mac --active-timeout 180 --idle-timeout 60 --out ${GNAT_OUTPUT_DIR}/${GNAT_OBSERVATION_TAG} --lock"
fi

export LTDL_LIBRARY_PATH=/opt/gnat/lib/yaf

if [ ! -z "${GNAT_PCAP_LIST}" ]; then
    /opt/gnat/bin/gnat_yaf ${GNAT_INPUT_SPEC} ${GNAT_OPTIONS}
    echo "finished processing pcap list: ${GNAT_PCAP_LIST}"
    # if in pcap procesing mode, then sleep until the service is explicity shut down
    while true
    do
        sleep 1
    done
else
    /opt/gnat/bin/gnat_sensor ${GNAT_INPUT_SPEC} ${GNAT_OPTIONS} --rotate ${GNAT_EXPORT_INTERVAL} 
fi
