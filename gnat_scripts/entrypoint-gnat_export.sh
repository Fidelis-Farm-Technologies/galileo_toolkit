#!/bin/bash

if [ ! -z "${GNAT_INPUT}" ] && [ ! -d "${GNAT_INPUT}" ]; then
    mkdir ${GNAT_INPUT}
fi

if [ ! -z "${GNAT_OUTPUT}" ] && [ ! -d "${GNAT_OUTPUT}" ]; then
    mkdir ${GNAT_OUTPUT}
fi

if [ ! -z "${GNAT_PASS}" ] && [ ! -d "${GNAT_PASS}" ]; then
    mkdir ${GNAT_PASS}
fi

COMMANDLINE_OPTIONS=""
if [ ! -z "${GNAT_PASS}" ]; then
    COMMANDLINE_OPTIONS="--pass ${GNAT_PASS}"
fi

if [ ! -z "${GNAT_INTERVAL}" ]; then
    COMMANDLINE_OPTIONS="${COMMANDLINE_OPTIONS} --interval ${GNAT_INTERVAL}"
fi


if [ ! -z "${GNAT_OPTIONS}" ]; then
    COMMANDLINE_OPTIONS="${COMMANDLINE_OPTIONS} --options ${GNAT_OPTIONS}"
fi

/opt/gnat/bin/gnat_export \
    --input ${GNAT_INPUT} \
    --output ${GNAT_OUTPUT} \
    ${COMMANDLINE_OPTIONS}

