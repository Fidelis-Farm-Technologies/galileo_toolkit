/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use clap::Parser;
use gnat::core::collect::collect;
use gnat::core::export::export;
use gnat::core::import::import;
use std::path::Path;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    host: Option<String>,

    #[arg(long)]
    port: Option<String>,

    #[arg(long)]
    transport: Option<String>,

    #[arg(long)]
    output: String,

    #[arg(long)]
    observation: Option<String>,

    #[arg(long)]
    rotate_interval: Option<u32>,

    #[arg(long)]
    verbose: Option<bool>,

    #[arg(long)]
    ssl_ca_file: Option<String>,

    #[arg(long)]
    ssl_cert_file: Option<String>,

    #[arg(long)]
    ssl_key_file: Option<String>,

    #[arg(long)]
    ssl_key_pass: Option<String>,

    #[arg(long)]
    asn: Option<String>,

    #[arg(long)]
    country: Option<String>,
}

fn main() {
    let args = Args::parse();
    let host_spec = args.host.unwrap_or("127.0.0.1".to_string()).clone();
    let output_spec = args.output.clone();
    let observation = args.observation.unwrap().clone();
    let asn_spec = args.asn.unwrap_or(String::new()).clone();
    let country_spec = args.country.unwrap_or(String::new()).clone();
    let rotate_spec = args.rotate_interval.unwrap_or(60).clone();
    let verbose_spec = args.verbose.unwrap_or(false).clone();
    let port_spec = args.port.unwrap_or("4739".to_string()).clone();
    let transport_spec = args.transport.unwrap_or("tcp".to_string()).clone();
    let ssl_ca_file_spec = args.ssl_ca_file.unwrap_or("".to_string()).clone();
    let ssl_cert_file_spec = args.ssl_cert_file.unwrap_or("".to_string()).clone();
    let ssl_key_file_spec = args.ssl_key_file.unwrap_or("".to_string()).clone();
    let ssl_key_pass_spec = args.ssl_key_pass.unwrap_or("".to_string()).clone();

    //
    // verify the combination of arguments are valid
    //

    if !Path::new(&host_spec).is_dir() && !Path::new(&host_spec).is_file() {
        eprintln!("error: invalid --host {}", host_spec);
        std::process::exit(exitcode::CONFIG)
    }

    if Path::new(&host_spec).is_file() && !Path::new(&output_spec).is_file() {
        eprintln!("error: --host <file spec> requires --output <file spec>");
        std::process::exit(exitcode::CONFIG)
    }

    if Path::new(&host_spec).is_dir() && !Path::new(&output_spec).is_dir() {
        eprintln!("error: --host <dir spec> requires --output <dir spec>");
        std::process::exit(exitcode::CONFIG)
    }

    if !Path::new(&output_spec).is_dir() && !Path::new(&output_spec).is_file() {
        eprintln!("error: invalid --output {}", output_spec);
        std::process::exit(exitcode::CONFIG)
    }

    let _ = collect(
        &observation,
        &host_spec,
        &port_spec,
        &transport_spec,
        &ssl_ca_file_spec,
        &ssl_cert_file_spec,
        &ssl_key_file_spec,
        &ssl_key_pass_spec,
        rotate_spec,
        verbose_spec,
        &output_spec,
        &asn_spec,
        &country_spec,
    );
}
