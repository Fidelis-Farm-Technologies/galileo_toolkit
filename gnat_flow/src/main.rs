/*
 * Galileo Network Analytics (GNA) Toolkit
 * 
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

extern crate c_string;
extern crate exitcode;
extern crate libc;

use crate::galileo::export::export;
use crate::galileo::import::import;
use clap::Parser;
use std::path::Path;

mod galileo;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    command: String,

    #[arg(long)]
    input: String,

    #[arg(long)]
    output: Option<String>,

    #[arg(long)]
    observation: Option<String>,

    #[arg(long)]
    uri: Option<String>,

    #[arg(long)]
    processed: Option<String>,

    #[arg(long)]
    polling: Option<bool>,

    #[arg(long)]
    asn: Option<String>,

    #[arg(long)]
    country: Option<String>,

    #[arg(long)]
    format: Option<String>,
}

fn parse_command() {
    let args = Args::parse();

    let command_spec = args.command.clone();
    let input_spec = args.input.clone();
    let output_spec = args.output.unwrap_or(String::new()).clone();
    let uri_spec = args.uri.unwrap_or(String::new()).clone();
    let processed_spec = args.processed.unwrap_or(String::new()).clone();
    let polling = args.polling.unwrap_or(false).clone();

    //
    // verify the combination of arguments are valid
    //
    if !output_spec.is_empty() && !uri_spec.is_empty() {
        eprintln!("error: --output <spec> and --uri <spec>  options are mutually exclusive");
        std::process::exit(exitcode::CONFIG)
    }

    if output_spec.is_empty() && uri_spec.is_empty() {
        eprintln!("error: --output <spec> or --uri <spec>  required",);
        std::process::exit(exitcode::CONFIG)
    }

    if !Path::new(&input_spec).is_dir() && !Path::new(&input_spec).is_file() {
        eprintln!("error: invalid --input {}", input_spec);
        std::process::exit(exitcode::CONFIG)
    }

    if !Path::new(&output_spec).is_dir()
        && !Path::new(&output_spec).is_file()
        && uri_spec.is_empty()
    {
        eprintln!("error: invalid --output {}", output_spec);
        std::process::exit(exitcode::CONFIG)
    }

    if Path::new(&input_spec).is_file() && !Path::new(&output_spec).is_file() && uri_spec.is_empty()
    {
        eprintln!("error: --input <file spec> requires --output <file spec>");
        std::process::exit(exitcode::CONFIG)
    }

    if Path::new(&input_spec).is_dir() && !Path::new(&output_spec).is_dir() && uri_spec.is_empty() {
        eprintln!("error: --input <dir spec> requires --output <dir spec>");
        std::process::exit(exitcode::CONFIG)
    }

    if polling == true && processed_spec.is_empty() {
        eprintln!("error: --processed_dir <dir spec> required when polling is active");
        std::process::exit(exitcode::CONFIG)
    }

    if !processed_spec.is_empty() && !Path::new(&processed_spec).is_dir() {
        eprintln!(
            "error: --processed_dir {} is not a valid directory",
            processed_spec
        );
        std::process::exit(exitcode::CONFIG)
    }

    match command_spec.as_str() {
        "import" => {
            let observation = args.observation.unwrap().clone();
            let asn = args.asn.unwrap_or(String::new()).clone();
            let country = args.country.unwrap_or(String::new()).clone();  
            let _ = import(
                &observation,
                &input_spec,
                &output_spec,
                &processed_spec,
                polling,
                &asn,
                &country,
            );
        }
        "export" => {
            let format = args.format.clone().unwrap_or("json".to_string());
            if format == "questdb" {
                let _ = export(&input_spec, &uri_spec, &processed_spec, polling, &format);
            } else {
                let _ = export(&input_spec, &output_spec, &processed_spec, polling, &format);
            }
        }
        _ => {
            eprintln!("error: invalid --command <option>");
            std::process::exit(exitcode::CONFIG)
        }
    }
}
fn main() {
    parse_command();
}
