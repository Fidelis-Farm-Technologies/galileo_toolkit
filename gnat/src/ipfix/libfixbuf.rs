/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

extern crate c_string;
extern crate libc;

use std::ffi::CString;
use std::os::raw::c_char;
// C functions wrappering libfixbuf operations

extern "C" {
    fn libfixbuf_file_import(
        command: *const c_char,
        observation: *const c_char,
        input_file: *const c_char,
        output_file: *const c_char,
        asn_file: *const c_char,
        country_file: *const c_char,
    ) -> i32;

    fn libfixbuf_socket_import(
        command: *const c_char,
        observation: *const c_char,
        host_spec: *const c_char,
        port_spec: *const c_char,
        transport_spec: *const c_char,
        ssl_ca_file: *const c_char,
        ssl_cert_file: *const c_char,
        ssl_key_file: *const c_char,
        ssl_key_pass: *const c_char,
        rotate_interval: u32,
        verbose: u32,
        output_spec: *const c_char,
        asn_file: *const c_char,
        country_file: *const c_char,
    ) -> i32;
}

pub fn unsafe_ipfix_file_import(
    command: &str,
    input_file: &str,
    output_dir: &str,
    observation: &str,
    asn: &str,
    country: &str,
) -> i32 {
    let c_command = CString::new(command).expect("converting to c_string");
    let c_observation = CString::new(observation).expect("converting to c_string");
    let c_asn_file = CString::new(asn).expect("converting to c_string");
    let c_country_file = CString::new(country).expect("converting to c_string");
    let c_input_file = CString::new(input_file).expect("converting to c_string");
    let c_output_dir = CString::new(output_dir).expect("converting to c_string");

    unsafe {
        libfixbuf_file_import(
            c_command.as_c_str().as_ptr(),
            c_observation.as_c_str().as_ptr(),
            c_input_file.as_c_str().as_ptr(),
            c_output_dir.as_c_str().as_ptr(),
            c_asn_file.as_c_str().as_ptr(),
            c_country_file.as_c_str().as_ptr(),
        )
    }
}

pub fn unsafe_ifpix_socket_import(
    command: &str,
    observation_tag: &str,
    host_spec: &str,
    port_spec: &str,
    transport_spec: &str,
    ssl_ca_file: &str,
    ssl_cert_file: &str,
    ssl_key_file: &str,
    ssl_key_pass: &str,
    rotate_interval: u32,
    verbose_mode: bool,
    output_spec: &str,
    asn_spec: &str,
    country_spec: &str,
) -> i32 {
    let c_command = CString::new(command).expect("converting to c_string");
    let c_observation = CString::new(observation_tag).expect("converting to c_string");
    let c_host_spec = CString::new(host_spec).expect("converting to c_string");
    let c_port_spec = CString::new(port_spec).expect("converting to c_string");
    let c_transport_spec = CString::new(transport_spec).expect("converting to c_string");
    let c_ssl_ca_file = CString::new(ssl_ca_file).expect("converting to c_string");
    let c_ssl_cert_file = CString::new(ssl_cert_file).expect("converting to c_string");
    let c_ssl_key_file = CString::new(ssl_key_file).expect("converting to c_string");
    let c_ssl_key_pass = CString::new(ssl_key_pass).expect("converting to c_string");
    let c_output_spec = CString::new(output_spec).expect("converting to c_string");
    let c_asn_spec = CString::new(asn_spec).expect("converting to c_string");
    let c_country_spec = CString::new(country_spec).expect("converting to c_string");

    let mut verbose: u32 = 0;
    if verbose_mode {
        verbose = 1;
    }

    unsafe {
        libfixbuf_socket_import(
             c_command.as_c_str().as_ptr(),
            c_observation.as_c_str().as_ptr(),
            c_host_spec.as_c_str().as_ptr(),
            c_port_spec.as_c_str().as_ptr(),
            c_transport_spec.as_c_str().as_ptr(),
            c_ssl_ca_file.as_c_str().as_ptr(),
            c_ssl_cert_file.as_c_str().as_ptr(),
            c_ssl_key_file.as_c_str().as_ptr(),
            c_ssl_key_pass.as_c_str().as_ptr(),
            rotate_interval,
            verbose,
            c_output_spec.as_c_str().as_ptr(),
            c_asn_spec.as_c_str().as_ptr(),
            c_country_spec.as_c_str().as_ptr(),
        )
    }
}
