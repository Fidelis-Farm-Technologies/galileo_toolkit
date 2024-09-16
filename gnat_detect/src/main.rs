/*
 * Galileo Network Analytics (GNA) Toolkit
 * 
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

extern crate exitcode;

use crate::galileo::feature::feature;
use crate::galileo::inference::inference;
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
    processed_dir: Option<String>,

    #[arg(long)]
    polling: Option<bool>,
}

fn parse_command() {
    let args = Args::parse();

    let command_spec = args.command.clone();
    let input_spec = args.input.clone();
    let output_spec = args.output.clone().unwrap_or("".to_string());
    let processed_spec = args.processed_dir.clone().unwrap_or("".to_string());
    let polling = args.polling.clone().unwrap_or(false);

    //
    // verify the combination of arguments are valid
    //

    if output_spec.is_empty() {
        eprintln!("error: --output <spec>  required",);
        std::process::exit(exitcode::CONFIG)
    }

    if !Path::new(&input_spec).is_dir() && !Path::new(&input_spec).is_file() {
        eprintln!("error: invalid --input {}", input_spec);
        std::process::exit(exitcode::CONFIG)
    }

    if !Path::new(&output_spec).is_dir() && !Path::new(&output_spec).is_file() {
        eprintln!("error: invalid --output {}", output_spec);
        std::process::exit(exitcode::CONFIG)
    }

    if Path::new(&input_spec).is_file() && !Path::new(&output_spec).is_file() {
        eprintln!("error: --input <file spec> requires --output <file spec>");
        std::process::exit(exitcode::CONFIG)
    }

    if Path::new(&input_spec).is_dir() && !Path::new(&output_spec).is_dir() {
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
        "feature" => {
            let _ = feature(&input_spec, &output_spec, &processed_spec, polling);
        }
        "inference" => {
            let _ = inference(&input_spec, &output_spec, &processed_spec, polling);
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
