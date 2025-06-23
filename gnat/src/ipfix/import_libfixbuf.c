/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

/*
 * YAF file processor using fixbuf library.
 * See: https://tools.netsa.cert.org/fixbuf/libfixbuf/
 */
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#include "yaf_record.h"
#include "yaf_template.h"

#include "import_libfixbuf.h"
#include "export_parquet.h"
#include "io_context.h"

#if defined(ENABLE_PROCESS_STATS)
static int processYafStatsRecord(const FILE *output_fp, const YAF_STATS_RECORD *yaf_stats_record)
{
    return 0;
}
#endif

static fbConnSpec_t g_collector_spec = FB_CONNSPEC_INIT;

static gboolean
ycNewConnection(
    fbListener_t *listener,
    void **ctx,
    int fd,
    struct sockaddr *peer,
    size_t peerlen,
    GError **err)
{
    if (!listener || !ctx)
        return FALSE;
    return TRUE;
}

void ycCloseConnection(void *ctx)
{
}

static gboolean
ycOpenListener(
    MIOSource *source,
    void *ctx,
    uint32_t *flags,
    GError **err)
{
    if (!ctx || !flags)
        return FALSE;
    GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;
    do
    {
        gnat->model = fbInfoModelAlloc();
        if (gnat->model == NULL)
            break;
        fbInfoModelAddElementArray(gnat->model, g_yaf_enterprise_elements);
        gnat->template = fbTemplateAlloc(gnat->model);
        if (gnat->template == NULL)
            break;
        if (fbTemplateAppendSpecArray(gnat->template, g_yaf_flow_spec, YTF_ALL, err) == FALSE)
            break;
        gnat->session = fbSessionAlloc(gnat->model);
        if (gnat->session == NULL)
            break;
        if (!fbSessionAddTemplate(gnat->session, TRUE, YAF_FLOW_FULL_TID, gnat->template, NULL, err))
            break;
        gnat->input_buf = fBufAllocForCollection(gnat->session, gnat->collector);
        if (gnat->input_buf == NULL)
            break;
        if (!fBufSetInternalTemplate(gnat->input_buf, YAF_FLOW_FULL_TID, err))
            break;
        gnat->listener = fbListenerAlloc(&gnat->connection_spec, gnat->session, ycNewConnection, ycCloseConnection, err);
        if (gnat->listener == NULL)
            break;
    } while (0);
    if (!gnat->listener)
    {
        if (gnat->collector)
            fbCollectorClose(gnat->collector);
        gnat->collector = NULL;
        if (gnat->template)
            fbTemplateFreeUnused(gnat->template);
        gnat->template = NULL;
        if (gnat->model)
            fbInfoModelFree(gnat->model);
        gnat->model = NULL;
        if (gnat->input_buf)
            fBufFree(gnat->input_buf);
        gnat->input_buf = NULL;
        *flags |= (MIO_F_CTL_ERROR | MIO_F_CTL_TERMINATE);
        return FALSE;
    }

    // initialize ndpi

    do
    {
        gnat->ndpi_ctx = ndpi_init_detection_module(NULL);
        if (gnat->ndpi_ctx == NULL)
        {
            fprintf(stderr, "%s: ndpi_init_detection_module() failed\n", __FUNCTION__);
            break;
        }

        NDPI_PROTOCOL_BITMASK protos;
        NDPI_BITMASK_SET_ALL(protos);
        ndpi_set_protocol_detection_bitmask2(gnat->ndpi_ctx, &protos);
        ndpi_finalize_initialization(gnat->ndpi_ctx);

        // GeoIP stuff

        //
        // maxmind ASN
        //
        memset(&gnat->asn_mmdb, 0, sizeof(gnat->asn_mmdb));
        if (strlen(gnat->asn_file))
        {
            if (MMDB_SUCCESS != MMDB_open(gnat->asn_file, MMDB_MODE_MMAP, &gnat->asn_mmdb))
            {
                fprintf(stderr, "%s: failed to load geolite - asn: %s\n", __FUNCTION__, gnat->asn_file);
                return FALSE;
            }
            gnat->asn_mmdb_ptr = &gnat->asn_mmdb;
        }
        //
        // maxmind Country
        //
        memset(&gnat->country_mmdb, 0, sizeof(gnat->country_mmdb));
        if (strlen(gnat->country_file))
        {
            if (MMDB_SUCCESS != MMDB_open(gnat->country_file, MMDB_MODE_MMAP, &gnat->country_mmdb))
            {
                fprintf(stderr, "%s: failed to load geolite - country: %s\n", __FUNCTION__, gnat->country_file);
                return FALSE;
            }
            gnat->country_mmdb_ptr = &gnat->country_mmdb;
        }
        return TRUE;
    } while (0);
    fprintf(stderr, "%s: failed\n", __FUNCTION__);
    return FALSE;
}

static gboolean
ycCloseListener(
    MIOSource *source,
    void *ctx,
    uint32_t *flags,
    GError **err)
{
    if (!ctx)
        return FALSE;
    GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;
    if (gnat)
    {
        if (gnat->asn_mmdb_ptr)
            MMDB_close(&gnat->asn_mmdb);

        if (gnat->country_mmdb_ptr)
            MMDB_close(&gnat->country_mmdb);

        if (gnat->ndpi_ctx)
            ndpi_exit_detection_module(gnat->ndpi_ctx);

        if (gnat->listener)
            fbListenerFree(gnat->listener);

        if (gnat->collector)
            fbCollectorClose(gnat->collector);

        if (gnat->template)
            fbTemplateFreeUnused(gnat->template);

        if (gnat->model)
            fbInfoModelFree(gnat->model);

        if (gnat->input_buf)
            fBufFree(gnat->input_buf);

        return TRUE;
    }
    fprintf(stderr, "%s: failed\n", __FUNCTION__);
    return FALSE;
}

static gboolean
ycOpenReader(
    MIOSource *source,
    void *ctx,
    uint32_t *flags,
    GError **err)
{
    if (!ctx || !flags)
        return FALSE;
    GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;
    do
    {
        gnat->model = fbInfoModelAlloc();
        if (gnat->model == NULL)
            break;
        fbInfoModelAddElementArray(gnat->model, g_yaf_enterprise_elements);
        gnat->template = fbTemplateAlloc(gnat->model);
        if (gnat->template == NULL)
            break;
        if (fbTemplateAppendSpecArray(gnat->template, g_yaf_flow_spec, YTF_ALL, err) == FALSE)
            break;
        gnat->session = fbSessionAlloc(gnat->model);
        if (gnat->session == NULL)
            break;
        if (!fbSessionAddTemplate(gnat->session, TRUE, YAF_FLOW_FULL_TID, gnat->template, NULL, err))
            break;
        if (!gnat->input_file || strlen(gnat->input_file) == 0)
        {
            fprintf(stderr, "%s: missing input file specifier\n", __FUNCTION__);
            break;
        }
        gnat->collector = fbCollectorAllocFile(NULL, gnat->input_file, err);
        if (gnat->collector == NULL)
        {
            fprintf(stderr, "%s: unable to open %s\n", __FUNCTION__, gnat->input_file);
            break;
        }
        gnat->input_buf = fBufAllocForCollection(gnat->session, gnat->collector);
        if (gnat->input_buf == NULL)
        {
            fprintf(stderr, "%s: unable to allocate buffer\n", __FUNCTION__);
            break;
        }
        if (!fBufSetInternalTemplate(gnat->input_buf, YAF_FLOW_FULL_TID, err))
        {
            fprintf(stderr, "%s: unable to set template\n", __FUNCTION__);
            break;
        }
    } while (0);
    if (!gnat->input_buf)
    {
        if (gnat->input_buf)
            fBufFree(gnat->input_buf);
        gnat->input_buf = NULL;
        if (gnat->collector)
            fbCollectorClose(gnat->collector);
        gnat->collector = NULL;
        if (gnat->template)
            fbTemplateFreeUnused(gnat->template);
        gnat->template = NULL;
        if (gnat->model)
            fbInfoModelFree(gnat->model);
        gnat->model = NULL;
        *flags |= (MIO_F_CTL_ERROR | MIO_F_CTL_TERMINATE);
        return FALSE;
    }

    // initialize ndpi
    do
    {
        gnat->ndpi_ctx = ndpi_init_detection_module(0);
        if (gnat->ndpi_ctx == NULL)
        {
            fprintf(stderr, "%s: ndpi_init_detection_module() failed\n", __FUNCTION__);
            break;
        }

        NDPI_PROTOCOL_BITMASK protos;
        NDPI_BITMASK_SET_ALL(protos);
        ndpi_set_protocol_detection_bitmask2(gnat->ndpi_ctx, &protos);
        ndpi_finalize_initialization(gnat->ndpi_ctx);

        // GeoIP stuff

        //
        // maxmind ASN
        //
        memset(&gnat->asn_mmdb, 0, sizeof(gnat->asn_mmdb));
        if (strlen(gnat->asn_file))
        {
            if (MMDB_SUCCESS != MMDB_open(gnat->asn_file, MMDB_MODE_MMAP, &gnat->asn_mmdb))
            {
                fprintf(stderr, "%s: failed to load geolite - asn: %s\n", __FUNCTION__, gnat->asn_file);
                break;
            }
            gnat->asn_mmdb_ptr = &gnat->asn_mmdb;
        }
        //
        // maxmind Country
        //
        memset(&gnat->country_mmdb, 0, sizeof(gnat->country_mmdb));
        if (strlen(gnat->country_file))
        {
            if (MMDB_SUCCESS != MMDB_open(gnat->country_file, MMDB_MODE_MMAP, &gnat->country_mmdb))
            {
                fprintf(stderr, "%s: failed to load geolite - country: %s\n", __FUNCTION__, gnat->country_file);
                break;
            }
            gnat->country_mmdb_ptr = &gnat->country_mmdb;
        }
        return TRUE;
    } while (0);
    fprintf(stderr, "%s: failed\n", __FUNCTION__);
    return FALSE;
}

static gboolean
ycCloseReader(
    MIOSource *source,
    void *ctx,
    uint32_t *flags,
    GError **err)
{
    if (!ctx)
        return FALSE;
    GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;
    if (gnat)
    {
        if (gnat->asn_mmdb_ptr)
            MMDB_close(&gnat->asn_mmdb);

        if (gnat->country_mmdb_ptr)
            MMDB_close(&gnat->country_mmdb);

        if (gnat->ndpi_ctx)
            ndpi_exit_detection_module(gnat->ndpi_ctx);

        if (gnat->collector)
            fbCollectorClose(gnat->collector);

        if (gnat->template)
            fbTemplateFreeUnused(gnat->template);

        if (gnat->model)
            fbInfoModelFree(gnat->model);

        if (gnat->input_buf)
            fBufFree(gnat->input_buf);

        return TRUE;
    }
    fprintf(stderr, "%s: failed\n", __FUNCTION__);
    return FALSE;
}

int libfixbuf_file_import(
    const char *command,    
    const char *observation,
    const char *input_file,
    const char *output_dir,
    const char *asn_file,
    const char *country_file,
    uint16_t risk_threshold)
{
    int rv = 0;
    GNAT_CONTEXT gnat;
    GError *err = NULL;
    MIOSource source;
    MIOSink sink;
    MIOAppDriver adrv;
    uint32_t miodflags = 0;

    // Defensive: zero-initialize all structs
    memset(&gnat, 0, sizeof(GNAT_CONTEXT));
    memset(&source, 0, sizeof(MIOSource));
    memset(&sink, 0, sizeof(MIOSink));
    memset(&adrv, 0, sizeof(MIOAppDriver));

    // Defensive: check strdup return values
    gnat.input_file = input_file ? strdup(input_file) : NULL;
    gnat.output_dir = output_dir ? strdup(output_dir) : NULL;
    gnat.asn_file = asn_file ? strdup(asn_file) : NULL;
    gnat.country_file = country_file ? strdup(country_file) : NULL;
    gnat.observation = observation ? strdup(observation) : NULL;
    gnat.risk_threshold = risk_threshold;

    /* set up logging */
    if (!logc_setup(&err))
    {
        if (err && err->message)
            air_opterr("%s", err->message);
    }

    /* initialize yafcollect context */
    gnat.input_buf = NULL;
    gnat.input_buf_ready = FALSE;
    gnat.outtime = 0;

    /* set up an app driver */
    adrv.app_open_source = ycOpenReader;
    adrv.app_close_source = ycCloseReader;
    adrv.app_open_sink = OpenFileSink;
    adrv.app_close_sink = CloseFileSink;
    adrv.app_process = ReaderToFileSink;

    g_message("%s: starting up", command);
    if (!mio_source_init_app(&source, mio_ov_in, MIO_T_APP, &gnat, &err))
    {
        if (err && err->message)
            air_opterr("libfixbuf_file_import: cannot set up MIO input: %s", err->message);
    }

    /* do dispatch here */
    if (!mio_dispatch_loop(&source,
                           &sink,
                           &adrv,
                           &gnat,
                           miodflags,
                           mio_ov_poll,
                           1,
                           mio_ov_poll))
    {
        rv = 1;
    }

    // Defensive: free all allocated memory and set pointers to NULL
    if (gnat.input_file)
    {
        free(gnat.input_file);
        gnat.input_file = NULL;
    }
    if (gnat.output_dir)
    {
        free(gnat.output_dir);
        gnat.output_dir = NULL;
    }
    if (gnat.asn_file)
    {
        free(gnat.asn_file);
        gnat.asn_file = NULL;
    }
    if (gnat.country_file)
    {
        free(gnat.country_file);
        gnat.country_file = NULL;
    }
    if (gnat.observation)
    {
        free(gnat.observation);
        gnat.observation = NULL;
    }

    g_message("%s: shutting down", command);

    if (gnat.ipfix_flows_skipped > 0)
    {
        fprintf(stderr, "%s: processed [%s] with %llu flows [skipped %llu IPv6 Hop-by-Hop]\n",
                command, input_file, (long long)gnat.ipfix_flows, (long long)gnat.ipfix_flows_skipped);
    }
    else
    {
        fprintf(stdout, "%s: processed [%s] with %llu flows\n",
                command, input_file, (long long)gnat.ipfix_flows);
    }

    fflush(stdout);
    return rv;
}

int libfixbuf_socket_import(
    const char *command,
    const char *observation,
    const char *host,
    const char *port,
    const char *transport,
    const char *ssl_ca_file,
    const char *ssl_cert_file,
    const char *ssl_key_file,
    const char *ssl_key_pass,
    int rotate_interval,
    int verbose,
    const char *output_dir,
    const char *asn_file,
    const char *country_file)
{
    int rv = 0;
    GNAT_CONTEXT gnat;
    GError *err = NULL;
    gboolean yac_tls = 0;
    MIOSource source;
    MIOSink sink;
    MIOAppDriver adrv;
    uint32_t miodflags = 0;

    memset(&source, 0, sizeof(MIOSource));
    memset(&sink, 0, sizeof(MIOSink));
    memset(&adrv, 0, sizeof(MIOAppDriver));
    memset(&gnat, 0, sizeof(GNAT_CONTEXT));

    // Defensive: check strdup return values
    gnat.connection_spec.host = host ? strdup(host) : NULL;
    gnat.connection_spec.svc = (port != NULL ? strdup(port) : strdup("4739"));
    gnat.connection_spec.ssl_ca_file = ssl_ca_file ? strdup(ssl_ca_file) : NULL;
    gnat.connection_spec.ssl_cert_file = ssl_cert_file ? strdup(ssl_cert_file) : NULL;
    gnat.connection_spec.ssl_key_file = ssl_key_file ? strdup(ssl_key_file) : NULL;
    gnat.connection_spec.ssl_key_pass = ssl_key_pass ? strdup(ssl_key_pass) : NULL;

    yac_tls = (ssl_cert_file != NULL ? 1 : 0);
    if (strcmp(transport, "tcp") == 0)
    {
        if (yac_tls)
        {
            gnat.connection_spec.transport = FB_TLS_TCP;
        }
        else
        {
            gnat.connection_spec.transport = FB_TCP;
        }
    }
    else if (strcmp(transport, "udp") == 0)
    {
        if (yac_tls)
        {
            gnat.connection_spec.transport = FB_DTLS_UDP;
        }
        else
        {
            gnat.connection_spec.transport = FB_UDP;
        }
    }
    else if (strcmp(transport, "sctp") == 0)
    {
        if (yac_tls)
        {
            gnat.connection_spec.transport = FB_DTLS_SCTP;
        }
        else
        {
            gnat.connection_spec.transport = FB_SCTP;
        }
    }
    else
    {
        air_opterr("%s: unsupported IPFIX transport protocol %s", command, transport);
    }

    /* set up logging */
    if (!logc_setup(&err))
    {
        if (err && err->message)
            air_opterr("%s", err->message);
    }

    /* fork if necessary */
    if (!daec_setup(&err))
    {
        if (err && err->message)
            air_opterr("%s", err->message);
    }

    /* initialize yafcollect context */
    gnat.input_buf = NULL;
    gnat.input_buf_ready = 0;
    gnat.outtime = 0;
    gnat.output_dir = output_dir ? strdup(output_dir) : NULL;
    gnat.asn_file = asn_file ? strdup(asn_file) : NULL;
    gnat.country_file = country_file ? strdup(country_file) : NULL;
    gnat.observation = observation ? strdup(observation) : NULL;
    gnat.verbose = (verbose ? 1 : 0);
    gnat.rotate_interval = (rotate_interval ? rotate_interval : 60);

    /* set up an app driver */
    adrv.app_open_source = ycOpenListener;
    adrv.app_close_source = ycCloseListener;
    adrv.app_open_sink = OpenFileSink;
    adrv.app_close_sink = CloseFileSink;
    adrv.app_process = SocketToFileSink;

    g_message("%s: starting up", command);

    /* create a source around a listener */
    if (!mio_source_init_app(&source, mio_ov_in, MIO_T_APP, &gnat, &err))
    {
        if (err && err->message)
            air_opterr("%s: cannot set up MIO input: %s", command,err->message);
    }

    g_message("libfixbuf_socket_import: loop");
    /* do dispatch here */
    if (!mio_dispatch_loop(&source,
                           &sink,
                           &adrv,
                           &gnat,
                           miodflags,
                           mio_ov_poll,
                           1,
                           mio_ov_poll))
    {
        rv = 1;
    }

    g_message("%s: shutting down", command);
    if (g_collector_spec.host)
        free(g_collector_spec.host);
    if (g_collector_spec.svc)
        free(g_collector_spec.svc);
    if (g_collector_spec.ssl_ca_file)
        free(g_collector_spec.ssl_ca_file);
    if (g_collector_spec.ssl_cert_file)
        free(g_collector_spec.ssl_cert_file);
    if (g_collector_spec.ssl_key_file)
        free(g_collector_spec.ssl_key_file);
    if (g_collector_spec.ssl_key_pass)
        free(g_collector_spec.ssl_key_pass);

    if (gnat.output_dir)
        free(gnat.output_dir);
    if (gnat.asn_file)
        free(gnat.asn_file);
    if (gnat.country_file)
        free(gnat.country_file);
    if (gnat.observation)
        free(gnat.observation);

    g_message("%s: processed %lu flows into %lu files", command, gnat.ipfix_flows, gnat.ipfix_files);
    return rv;
}
