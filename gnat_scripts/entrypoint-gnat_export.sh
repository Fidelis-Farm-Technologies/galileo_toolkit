#!/bin/bash

if [ ! -d  "/var/spool/exported" ]; then
    mkdir /var/spool/exported
fi

/opt/gnat/bin/gnat_flow \
    --command export \
    --polling true \
    --input "/var/spool/flow" \
    --format "questdb" \
    --uri ${GNAT_DB_URI} \
    --processed "/var/spool/exported"
