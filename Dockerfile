
# ---------------------------------------------------------------
#
# ---------------------------------------------------------------
FROM fidelismachine/galileo_base AS builder

# ---------------------------------------------------------------
# Stage 1
# ---------------------------------------------------------------
WORKDIR /builder
COPY . .

#
# setup pytorch environment
#
ENV LIBTORCH=/base/libtorch
#ENV LIBTORCH_INCLUDE=/base/libtorch
#ENV LIBTORCH_LIB=/base/libtorch
#ENV LD_LIBRARY_PATH=/base/libtorch

#
# build gnat toolkit
#
WORKDIR /builder/gnat
RUN cargo build --release


#
# Update the LD_LIBRARY_PATH
#
RUN echo "/opt/gnat/lib" > /etc/ld.so.conf.d/gnat.conf
RUN echo "/opt/gnat/lib/pytorch" > /etc/ld.so.conf.d/pytorch.conf
RUN ldconfig
    
# ---------------------------------------------------------------
# Stage 2
# ---------------------------------------------------------------
#FROM bitnami/minideb:bookworm AS runner
FROM bitnami/minideb:latest AS runner

RUN --mount=type=cache,target=/var/cache/apt \
	apt-get update \
    && apt-get install -yqq --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/gnat
RUN mkdir -p /opt/gnat/bin /opt/gnat/scripts /opt/gnat/etc /opt/gnat/lib/pytorch

COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_sensor.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_import.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_collect.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_merge.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_hbos.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_model.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_export.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_tag.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_sample.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_aggregate.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_rule.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_split.sh /opt/gnat/scripts/
COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_store.sh /opt/gnat/scripts/
#COPY --from=builder /builder/gnat_scripts/entrypoint-gnat_cache.sh /opt/gnat/scripts/

COPY --from=builder /builder/gnat_etc/protocols /etc
COPY --from=builder /usr/local/lib /opt/gnat/lib              
COPY --from=builder /opt/gnat/lib /opt/gnat/lib
COPY --from=builder /base/libtorch/lib /opt/gnat/lib/pytorch

COPY --from=builder /builder/gnat/target/release/gnat_collect /opt/gnat/bin/gnat_collect
COPY --from=builder /builder/gnat/target/release/gnat_import /opt/gnat/bin/gnat_import
COPY --from=builder /builder/gnat/target/release/gnat_export /opt/gnat/bin/gnat_export
COPY --from=builder /builder/gnat/target/release/gnat_merge /opt/gnat/bin/gnat_merge
COPY --from=builder /builder/gnat/target/release/gnat_sample /opt/gnat/bin/gnat_sample
COPY --from=builder /builder/gnat/target/release/gnat_aggregate /opt/gnat/bin/gnat_aggregate
COPY --from=builder /builder/gnat/target/release/gnat_hbos /opt/gnat/bin/gnat_hbos
COPY --from=builder /builder/gnat/target/release/gnat_model /opt/gnat/bin/gnat_model
COPY --from=builder /builder/gnat/target/release/gnat_tag /opt/gnat/bin/gnat_tag
COPY --from=builder /builder/gnat/target/release/gnat_rule /opt/gnat/bin/gnat_rule
COPY --from=builder /builder/gnat/target/release/gnat_split /opt/gnat/bin/gnat_split
COPY --from=builder /builder/gnat/target/release/gnat_store /opt/gnat/bin/gnat_store
#COPY --from=builder /builder/gnat/target/release/gnat_cache /opt/gnat/bin/gnat_cache


COPY --from=builder /opt/gnat/bin/yaf /opt/gnat/bin/gnat_sensor
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

