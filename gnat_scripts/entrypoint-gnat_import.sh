#!/bin/bash

GNAT_GEO_OPTIONS=
GNAT_GEO_ASN=/var/maxmind/GeoLite2-ASN.mmdb
GNAT_GEO_COUNTRY=/var/maxmind/GeoLite2-Country.mmdb

if [ -z "${GNAT_INPUT_DIR}" ]; then
    echo "Error: undefined environment variable GNAT_INPUT_DIR"
    exit 
fi

if [ -z "${GNAT_OUTPUT_DIR}" ]; then
    echo "Error: undefined environment variable GNAT_OUTPUT_DIR"
    exit 
fi

if [ -z "${GNAT_PROCESSED_DIR}" ]; then
    echo "Error: undefined environment variable GNAT_PROCESSED_DIR"
    exit 
fi

if [ ! -d "${GNAT_OUTPUT_DIR}" ]; then
    mkdir ${GNAT_OUTPUT_DIR}
fi

if [ ! -d "${GNAT_PROCESSED_DIR}" ]; then
    mkdir ${GNAT_PROCESSED_DIR}
fi

if [ -f ${GNAT_GEO_ASN} ]; then
  GNAT_GEO_OPTIONS="--asn ${GNAT_GEO_ASN}"
fi

if [ -f ${GNAT_GEO_COUNTRY} ]; then
   GNAT_GEO_OPTIONS="${GNAT_GEO_OPTIONS} --country ${GNAT_GEO_COUNTRY}"
fi

/opt/gnat/bin/gnat_flow \
    --command import \
    --observation ${GNAT_OBSERVATION_TAG} \
    --input ${GNAT_INPUT_DIR} \
    --output ${GNAT_OUTPUT_DIR} \
    --processed ${GNAT_PROCESSED_DIR} \
    --polling true \
    ${GNAT_GEO_OPTIONS}
    

