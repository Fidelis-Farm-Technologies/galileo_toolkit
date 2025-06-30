#!/bin/bash

if [ ! -z "${GNAT_INPUT_DIR}" ] && [ ! -d "${GNAT_INPUT_DIR}" ]; then
    mkdir ${GNAT_INPUT_DIR}
fi

if [ ! -z "${GNAT_PASS_DIR}" ] && [ ! -d "${GNAT_PASS_DIR}" ]; then
    mkdir ${GNAT_PASS_DIR}
fi

COMMANDLINE_OPTIONS=""
if [ ! -z "${GNAT_PASS_DIR}" ]; then
    COMMANDLINE_OPTIONS="--pass ${GNAT_PASS_DIR}"
fi

if [ ! -z "${GNAT_OPTIONS}" ]; then
    COMMANDLINE_OPTIONS="${COMMANDLINE_OPTIONS} --options ${GNAT_OPTIONS}"
fi

/opt/gnat/bin/gnat_store \
    --input ${GNAT_INPUT_DIR} \
    --output ${GNAT_OUTPUT_DIR} \
    --interval ${GNAT_INTERVAL} \
    ${COMMANDLINE_OPTIONS}

