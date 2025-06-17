/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

/*
 * To ensure interoperability the model was derived from 
 * the YAF project: ${YAF_PROJECT_DIR}/infomodel/cert.i
 */

/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
#pragma once

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>


int ipfix_file_import(const char *observation,
                 const char *input_file,
                 const char *output_dir,
                 const char *asn_file,
                 const char *country_file);

int ipfix_socket_import(
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
    const char *country_file);
