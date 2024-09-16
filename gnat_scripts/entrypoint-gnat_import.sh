#!/bin/bash

GNAT_GEO_OPTIONS=
GNAT_GEO_ASN=/var/maxmind/GeoLite2-ASN.mmdb
GNAT_GEO_COUNTRY=/var/maxmind/GeoLite2-Country.mmdb

if [ ! -d "/var/spool/flow" ]; then
    mkdir /var/spool/flow
fi

if [ -f ${GNAT_GEO_ASN} ]; then
  GNAT_GEO_OPTIONS="--asn ${GNAT_GEO_ASN}"
fi

if [ -f ${GNAT_GEO_COUNTRY} ]; then
   GNAT_GEO_OPTIONS="${GNAT_GEO_OPTIONS} --country ${GNAT_GEO_COUNTRY}"
fi


if [ ! -d  "/var/spool/imported" ]; then
    mkdir /var/spool/imported
fi

/opt/gnat/bin/gnat_flow \
    --command import \
    --polling true \
    --input "/var/spool/${GNAT_OBSERVATION_TAG}" \
    --output "/var/spool/flow" \
    --observation "${GNAT_OBSERVATION_TAG}" \
    --processed "/var/spool/imported" \
    ${GNAT_GEO_OPTIONS}
    

