#!/bin/bash

if [ -z "${GNAT_INPUT_DIR}" ]; then
    echo "Error: undefined environment variable GNAT_INPUT_DIR"
    exit 
fi

if [ -z "${GNAT_PROCESSED_DIR}" ]; then
    echo "Error: undefined environment variable GNAT_PROCESSED_DIR"
    exit 
fi

if [ ! -d  "${GNAT_PROCESSED_DIR}" ]; then
    mkdir -p ${GNAT_PROCESSED_DIR}
fi

if [ -z "${GNAT_QDB_POLLING}" ]; then
    GNAT_QDB_POLLING=60
fi
#
# Launch db exporter
#
/opt/gnat/bin/gnat_db \
    --input ${GNAT_INPUT_DIR} \
    --host ${GNAT_QDB_HOST} \
    --retention ${GNAT_QDB_RETENTION} \
    --processed ${GNAT_PROCESSED_DIR} \
    --polling ${GNAT_QDB_POLLING}

