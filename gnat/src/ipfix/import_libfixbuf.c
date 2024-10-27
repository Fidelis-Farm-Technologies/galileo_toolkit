/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
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

#include "yaf_record.h"
#include "yaf_template.h"

#include "import_libfixbuf.h"
#include "export_parquet.h"
#include "io_context.h"

#define GLIB_ERROR_RETURN(e)                         \
    {                                                \
        fprintf(stderr, "%s:%d: %s\n",               \
                __FUNCTION__, __LINE__, e->message); \
        break;                                       \
    }

#if defined(ENABLE_PROCESS_STATS)
static int processYafStatsRecord(const FILE *output_fp, const YAF_STATS_RECORD *yaf_stats_record)
{
    return 0;
}
#endif

static fbConnSpec_t collector_spec = FB_CONNSPEC_INIT;

static gboolean
ycNewConnection(
    fbListener_t *listener,
    void **ctx,
    int fd,
    struct sockaddr *peer,
    size_t peerlen,
    GError **err)

{
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

        gnat->listener = fbListenerAlloc(&gnat->connection_spec,
                                         gnat->session,
                                         ycNewConnection,
                                         ycCloseConnection,
                                         err);

        if (gnat->listener == NULL)
            break;
        // gnat->input_buf = fbListenerWait(gnat->listener, err)

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

    return TRUE;
}

static gboolean
ycCloseListener(
    MIOSource *source,
    void *ctx,
    uint32_t *flags,
    GError **err)
{
    GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;
    if (gnat)
    {
        if (gnat->collector)
            fbCollectorClose(gnat->collector);
        if (gnat->template)
            fbTemplateFreeUnused(gnat->template);
        if (gnat->model)
            fbInfoModelFree(gnat->model);
        if (gnat->input_buf)
            fBufFree(gnat->input_buf);
        if (gnat->listener)
            fbListenerFree(gnat->listener);
        return TRUE;
    }
    return FALSE;
}

static gboolean
ycOpenReader(
    MIOSource *source,
    void *ctx,
    uint32_t *flags,
    GError **err)
{
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

        if (!gnat->input_file || (strlen(gnat->input_file) == 0))
        {
            fprintf(stderr, "%s: missing input file specifier\n", __FUNCTION__);
            break;
        }

        gnat->collector = fbCollectorAllocFile(NULL, gnat->input_file, err);
        if (gnat->collector == NULL)
            break;

        gnat->input_buf = fBufAllocForCollection(gnat->session, gnat->collector);
        if (gnat->input_buf == NULL)
            break;

        if (!fBufSetInternalTemplate(gnat->input_buf, YAF_FLOW_FULL_TID, err))
            break;
    } while (0);

    if (!gnat->input_buf)
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

    return TRUE;
}

static gboolean
ycCloseReader(
    MIOSource *source,
    void *ctx,
    uint32_t *flags,
    GError **err)
{
    GNAT_CONTEXT *gnat = (GNAT_CONTEXT *)ctx;
    if (gnat)
    {
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
    return FALSE;
}

int libfixbuf_file_import(
    const char *observation,
    const char *input_file,
    const char *output_dir,
    const char *asn_file,
    const char *country_file)
{
    int rv = 0;
    GNAT_CONTEXT gnat;
    GError *err = NULL;
    MIOSource source;
    MIOSink sink;
    MIOAppDriver adrv;
    uint32_t miodflags = 0;

    memset(&source, 0, sizeof(MIOSource));
    memset(&sink, 0, sizeof(MIOSink));
    memset(&adrv, 0, sizeof(MIOAppDriver));
    memset(&gnat, 0, sizeof(GNAT_CONTEXT));

    /* set up logging */
    if (!logc_setup(&err))
    {
        air_opterr("%s", err->message);
    }

    /* initialize yafcollect context */
    gnat.input_buf = NULL;
    gnat.input_buf_ready = FALSE;
    gnat.outtime = 0;
    gnat.input_file = strdup(input_file);
    gnat.asn_file = strdup(asn_file);
    gnat.country_file = strdup(country_file);
    gnat.observation = (observation != NULL ? strdup(observation) : strdup("gnat"));

    /* set up an app driver */
    adrv.app_open_source = ycOpenReader;
    adrv.app_close_source = ycCloseReader;

    // callback
    adrv.app_open_sink = OpenFileSink;
    adrv.app_close_sink = CloseFileSink;
    adrv.app_process = ReaderToFileSink;

    g_message("libfixbuf_file_import: initializing");

    /* create a source around a listener */
    if (!mio_source_init_app(&source, mio_ov_in, MIO_T_APP, &gnat, &err))
    {
        air_opterr("libfixbuf_file_import: cannot set up MIO input: %s", err->message);
    }

    g_message("libfixbuf_file_import: starting up");
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

    g_message("libfixbuf_file_import: shutting down");
    if (gnat.observation)
        free(gnat.observation);
    if (gnat.input_file)
        free(gnat.input_file);
    if (gnat.asn_file)
        free(gnat.asn_file);
    if (gnat.country_file)
        free(gnat.country_file);

    g_message("libfixbuf_file_import: processed %lu flows into %lu files", gnat.ipfix_flows, gnat.ipfix_files);
    return rv;
}

int libfixbuf_socket_import(
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
    gboolean yac_tls = FALSE;
    MIOSource source;
    MIOSink sink;
    MIOAppDriver adrv;
    uint32_t miodflags = 0;

    memset(&source, 0, sizeof(MIOSource));
    memset(&sink, 0, sizeof(MIOSink));
    memset(&adrv, 0, sizeof(MIOAppDriver));
    memset(&gnat, 0, sizeof(GNAT_CONTEXT));

    gnat.connection_spec.host = strdup(host);
    gnat.connection_spec.svc = (port != NULL ? strdup(port) : strdup("4739"));
    gnat.connection_spec.ssl_ca_file = strdup(ssl_ca_file);
    gnat.connection_spec.ssl_cert_file = strdup(ssl_cert_file);
    gnat.connection_spec.ssl_key_file = strdup(ssl_key_file);
    gnat.connection_spec.ssl_key_pass = strdup(ssl_key_pass);

    yac_tls = (ssl_cert_file != NULL ? TRUE : FALSE);
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
        air_opterr("libfixbuf_socket_import: unsupported IPFIX transport protocol %s", transport);
    }

    /* set up logging */
    if (!logc_setup(&err))
    {
        air_opterr("%s", err->message);
    }

    /* fork if necessary */
    if (!daec_setup(&err))
    {
        air_opterr("%s", err->message);
    }

    /* initialize yafcollect context */
    gnat.input_buf = NULL;
    gnat.input_buf_ready = FALSE;
    gnat.outtime = 0;
    gnat.asn_file = strdup(asn_file);
    gnat.country_file = strdup(country_file);
    gnat.observation = (observation != NULL ? strdup(observation) : strdup("gnat"));
    gnat.verbose = (verbose ? TRUE : FALSE);
    gnat.rotate_interval = (rotate_interval ? rotate_interval : 60);

    /* set up an app driver */
    adrv.app_open_source = ycOpenListener;
    adrv.app_close_source = ycCloseListener;

    // callback
    adrv.app_open_sink = OpenFileSink;
    adrv.app_close_sink = CloseFileSink;
    adrv.app_process = SocketToFileSink;

    g_message("libfixbuf_socket_import: initializing");

    /* create a source around a listener */
    if (!mio_source_init_app(&source, mio_ov_in, MIO_T_APP, &gnat, &err))
    {
        air_opterr("libfixbuf_socket_import: cannot set up MIO input: %s", err->message);
    }

    g_message("libfixbuf_socket_import: starting up");
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

    g_message("libfixbuf_socket_import: shutting down");
    if (collector_spec.host)
        free(collector_spec.host);
    if (collector_spec.svc)
        free(collector_spec.svc);
    if (collector_spec.ssl_ca_file)
        free(collector_spec.ssl_ca_file);
    if (collector_spec.ssl_cert_file)
        free(collector_spec.ssl_cert_file);
    if (collector_spec.ssl_key_file)
        free(collector_spec.ssl_key_file);
    if (collector_spec.ssl_key_pass)
        free(collector_spec.ssl_key_pass);
    if (gnat.observation)
        free(gnat.observation);
    if (gnat.input_file)
        free(gnat.input_file);
    if (gnat.asn_file)
        free(gnat.asn_file);
    if (gnat.country_file)
        free(gnat.country_file);

    g_message("libfixbuf_socket_import: processed %lu flows into %lu files", gnat.ipfix_flows, gnat.ipfix_files);
    return rv;
}
