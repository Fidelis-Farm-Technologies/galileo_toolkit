#!/bin/bash

if [ -z "${GNAT_INPUT_DIR}" ]; then
    echo "Error: undefined environment variable GNAT_INPUT_DIR"
    exit 
fi

if [ -z "${GNAT_OUTPUT_DIR}" ]; then
    echo "Error: undefined environment variable GNAT_OUTPUT_DIR"
    exit 
fi

if [ ! -d "${GNAT_OUTPUT_DIR}" ]; then
    mkdir ${GNAT_OUTPUT_DIR}
fi

if [ -z "${GNAT_BATCH_INTERVAL}" ]; then
    GNAT_BATCH_INTERVAL=60
fi

/opt/gnat/bin/gnat_batch \
    --input ${GNAT_INPUT_DIR} \
    --output ${GNAT_OUTPUT_DIR} \
    --minutes ${GNAT_BATCH_INTERVAL} 
    

