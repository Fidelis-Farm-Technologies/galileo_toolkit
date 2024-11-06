
# ---------------------------------------------------------------
#
# ---------------------------------------------------------------
FROM fidelismachine/gnat_base AS builder

# ---------------------------------------------------------------
# Stage 1
# ---------------------------------------------------------------
WORKDIR /builder
COPY . .

#
# build gnat_flow
#
WORKDIR /builder/gnat
RUN cargo build --release

#
# build gnat_db
#
WORKDIR /builder/gnat_db
RUN cargo build --release

#
# build gnat_detect
#
ENV LIBTORCH=/base/libtorch
ENV LIBTORCH_INCLUDE=/base/libtorch
ENV LIBTORCH_LIB=/base/libtorch
ENV LD_LIBRARY_PATH=/base/libtorch

#WORKDIR /builder/gnat_ai
#RUN cargo build --release

#
# Update the LD_LIBRARY_PATH
#
RUN echo "/opt/gnat/lib" > /etc/ld.so.conf.d/gnat.conf
RUN echo "/opt/gnat/lib/pytorch" > /etc/ld.so.conf.d/pytorch.conf
RUN ldconfig
    
# ---------------------------------------------------------------
# Stage 2
# ---------------------------------------------------------------
FROM bitnami/minideb:bookworm AS runner

WORKDIR /opt/gnat
RUN mkdir -p /opt/gnat/bin /opt/gnat/scripts /opt/gnat/etc /opt/gnat/lib/pytorch

COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_yaf.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_import.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_collect.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_db.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_batch.sh /opt/gnat/scripts/

COPY --from=builder /builder/gnat_etc/protocols /etc
COPY --from=builder /usr/local/lib /opt/gnat/lib              
COPY --from=builder /opt/gnat/lib /opt/gnat/lib
COPY --from=builder /base/libtorch/lib /opt/gnat/lib/pytorch

COPY --from=builder /builder/gnat/target/release/gnat_collect /opt/gnat/bin/gnat_collect
COPY --from=builder /builder/gnat/target/release/gnat_import /opt/gnat/bin/gnat_import
COPY --from=builder /builder/gnat/target/release/gnat_export /opt/gnat/bin/gnat_export
COPY --from=builder /builder/gnat/target/release/gnat_batch /opt/gnat/bin/gnat_batch
COPY --from=builder /builder/gnat_db/target/release/gnat_db /opt/gnat/bin/gnat_db
#COPY --from=builder /builder/gnat_ai/target/release/gnat_ai /opt/gnat/bin/gnat_ai
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

