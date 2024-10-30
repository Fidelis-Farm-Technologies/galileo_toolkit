/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */
use crate::ipfix::libfixbuf::unsafe_ifpix_socket_import;

pub fn collect(
    observation_tag: &String,
    host_spec: &String,
    port_spec: &String,
    transport_spec: &String,
    ssl_ca_file: &String,
    ssl_cert_file: &String,
    ssl_key_file: &String,
    ssl_key_pass: &String,
    rotate_interval: u32,
    verbose_mode: bool,
    output_spec: &String,
    asn_spec: &String,
    country_spec: &String,
) -> Result<(), std::io::Error> {


    println!("\tobservation: {}", observation_tag);
    println!("\thost spec: {}", host_spec);
    println!("\tport spec: {}", port_spec);
    println!("\ttransport spec: {}", transport_spec);
    if ssl_ca_file.is_empty() {
        println!("\tssl_ca_file: {}", ssl_ca_file);
    }
    if ssl_cert_file.is_empty() {
        println!("\tssl_cert_file: {}", ssl_cert_file);
    }
    if ssl_key_file.is_empty() {
        println!("\tssl_key_file: {}", ssl_key_file);
    }
    if ssl_key_pass.is_empty() {
        println!("\tssl_key_pass: {}", ssl_key_pass);
    }            
    println!("\toutput spec: {}", output_spec);
    println!("\tasn file: {}", asn_spec);
    println!("\tcountry file: {}", country_spec);
    println!("\rotate_interval: {}", rotate_interval);

    let status = unsafe_ifpix_socket_import(
        &observation_tag,
        &host_spec,
        &port_spec,
        &transport_spec,
        &ssl_ca_file,
        &ssl_cert_file,
        &ssl_key_file,
        &ssl_key_pass,
        rotate_interval,
        verbose_mode,
        &output_spec,
        &asn_spec,
        &country_spec,
    );
    if status < 0 {
        eprintln!("error: collector failure");
      
    } 
    Ok(())
}
