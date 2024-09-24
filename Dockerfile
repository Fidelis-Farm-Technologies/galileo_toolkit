
# ---------------------------------------------------------------
#
# ---------------------------------------------------------------
FROM gnat_toolkit AS builder
FROM bitnami/minideb:bookworm AS runner

# ---------------------------------------------------------------
#
# ---------------------------------------------------------------

WORKDIR /gnat_scripts
COPY gnat_scripts .

WORKDIR /opt/gnat
RUN mkdir -p /opt/gnat/bin /opt/gnat/scripts /opt/gnat/etc /opt/gnat/lib/pytorch

COPY /gnat_scripts/entrypoint-gnat_yaf.sh /opt/gnat/scripts/
COPY /gnat_scripts/entrypoint-gnat_import.sh /opt/gnat/scripts/
COPY /gnat_scripts/entrypoint-gnat_db.sh /opt/gnat/scripts/

COPY --from=builder /builder/gnat_etc/protocols /etc
COPY --from=builder /usr/local/lib /opt/gnat/lib              
COPY --from=builder /opt/gnat/lib /opt/gnat/lib
COPY --from=builder /base/libtorch/lib /opt/gnat/lib/pytorch

COPY --from=builder /builder/gnat_flow/target/release/gnat_flow /opt/gnat/bin/gnat_flow
COPY --from=builder /builder/gnat_detect/target/release/gnat_detect /opt/gnat/bin/gnat_detect
COPY --from=builder /builder/gnat_db/target/release/gnat_db /opt/gnat/bin/gnat_db
COPY --from=builder /opt/gnat/bin/yaf /opt/gnat/bin/gnat_yaf
COPY --from=builder /usr/local/bin/duckdb /opt/gnat/bin/duckdb

COPY --from=builder \
    /lib/libndpi.so.4 \
    /usr/lib/x86_64-linux-gnu/libpcap.so.1.10.3 \
    /usr/lib/x86_64-linux-gnu/libglib-2.0.so.0 \
    /usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2 \
    /usr/lib/x86_64-linux-gnu/libpcre.so.3.13.3 \
    /usr/lib/x86_64-linux-gnu/libdbus-1.so.3.32.4 \
    /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
    /usr/lib/x86_64-linux-gnu/libssl.so.3 \
    /usr/lib/x86_64-linux-gnu/

RUN echo "/opt/gnat/lib" > /etc/ld.so.conf.d/gnat.conf
RUN echo "/opt/gnat/lib/yaf" > /etc/ld.so.conf.d/yaf.conf
RUN echo "/opt/gnat/lib/pytorch" > /etc/ld.so.conf.d/pytorch.conf
RUN ldconfig

