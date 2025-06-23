/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use std::io::Error;

use crate::ipfix::libfixbuf::unsafe_ifpix_socket_import;
use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::FileType;
use crate::pipeline::Interval;
use duckdb::Connection;

pub struct CollectorProcessor {
    pub command: String,
    pub host: String,
    pub output: String,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
    pub port: String,
    pub transport: String,
    pub observation: String,
    pub asn: String,
    pub country: String,
    pub ssl_ca_file: String,
    pub ssl_cert_file: String,
    pub ssl_key_file: String,
    pub ssl_key_pass: String,
    pub rotate_interval: u32,
    pub verbose: bool,
}

impl CollectorProcessor {
    pub fn new<'a>(
        command: &str,
        host: &str,
        output: &str,
        pass: &str,
        interval_string: &str,
        extension_string: &str,
        options_string: &str,
    ) -> Result<Self, Error> {
        let interval = parse_interval(interval_string);
        let mut options = parse_options(options_string);

        // default options
        options.entry("observation").or_insert("gnat");
        options.entry("asn").or_insert("");
        options.entry("country").or_insert("");
        options.entry("port").or_insert("4739");
        options.entry("transport").or_insert("tcp");
        options.entry("ssl_ca_file").or_insert("");
        options.entry("ssl_cert_file").or_insert("");
        options.entry("ssl_key_file").or_insert("");
        options.entry("ssl_key_pass").or_insert("");
        options.entry("rotate_interval").or_insert("60");
        options.entry("verbose").or_insert("false");

        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}={}]", command, key, value);
            }
        }

        let observation = options.get("observation").expect("expected observation");
        let asn = options.get("asn").expect("expected asn");
        let country = options.get("country").expect("expected country");
        let transport = options.get("transport").expect("expected asn");
        let port = options.get("port").expect("expected port");
        let ssl_ca_file = options.get("ssl_ca_file").expect("expected ssl_ca_file");
        let ssl_cert_file = options
            .get("ssl_cert_file")
            .expect("expected ssl_cert_file");
        let ssl_key_file = options.get("ssl_key_file").expect("expected ssl_key_file");
        let ssl_key_pass = options.get("ssl_key_pass").expect("expected ssl_key_pass");
        let rotate_interval = options
            .get("rotate_interval")
            .expect("expected rotate_interval")
            .parse::<u32>()
            .unwrap();
        let verbose = options
            .get("verbose")
            .expect("expected verbose")
            .parse::<bool>()
            .unwrap();

        Ok(Self {
            command: command.to_string(),
            host: host.to_string(),
            output: output.to_string(),
            pass: pass.to_string(),
            interval,
            extension: extension_string.to_string(),
            port: port.to_string(),
            transport: transport.to_string(),
            observation: observation.to_string(),
            asn: asn.to_string(),
            country: country.to_string(),
            ssl_ca_file: ssl_ca_file.to_string(),
            ssl_cert_file: ssl_cert_file.to_string(),
            ssl_key_file: ssl_key_file.to_string(),
            ssl_key_pass: ssl_key_pass.to_string(),
            rotate_interval,
            verbose,
        })
    }
}
impl FileProcessor for CollectorProcessor {
    fn get_command(&self) -> &String {
        &self.command
    }
    fn get_input(&self) -> &String {
        &self.host
    }
    fn get_output(&self) -> &String {
        &self.output
    }
    fn get_pass(&self) -> &String {
        &self.pass
    }
    fn get_interval(&self) -> &Interval {
        &self.interval
    }
    fn get_file_extension(&self) -> &String {
        &self.extension
    }
    fn socket(&mut self) -> Result<(), Error> {
        let status = unsafe_ifpix_socket_import(
            &self.command,
            &self.observation,
            &self.host,
            &self.port,
            &self.transport,
            &self.ssl_ca_file,
            &self.ssl_cert_file,
            &self.ssl_key_file,
            &self.ssl_key_pass,
            self.rotate_interval,
            self.verbose,
            &self.output,
            &self.asn,
            &self.country,
        );
        if status < 0 {
            Err(Error::new(
                std::io::ErrorKind::Other,
                "collector failed: unsafe_ifpix_socket_import returned < 0",
            ))
        } else {
            Ok(())
        }
    }
    fn delete_files(&self) -> bool {
        true
    }
    fn process(
        &mut self,
        _file_list: &Vec<String>,
        _schema_version: FileType,
    ) -> Result<(), Error> {
        Err(Error::new(
            std::io::ErrorKind::Other,
            "CollectorProcessor::process is not implemented",
        ))
    }
}

/*


pub fn process_files(
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
        eprintln!("Error: collector failure");

    }
    Ok(())
}
 */
