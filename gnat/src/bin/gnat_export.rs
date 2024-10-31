/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use clap::Parser;
use std::path::Path;
use gnat::core::export::export;


#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    input: String,

    #[arg(long)]
    output: String,

    #[arg(long)]
    processed: Option<String>,

    #[arg(long)]
    rotate_interval: Option<u32>,

    #[arg(long)]
    polling: Option<bool>,

    #[arg(long)]
    verbose: Option<bool>,

    #[arg(long)]
    format: Option<String>,
}

fn main() {
    let args = Args::parse();
    let input_spec = args.input.clone();
    let output_spec = args.output.clone();
    let processed_spec = args.processed.unwrap_or(String::new()).clone();
    let format = args.format.clone().unwrap_or("json".to_string());
    let polling = args.polling.unwrap_or(false).clone();

    //
    // verify the combination of arguments are valid
    //

    if !Path::new(&input_spec).is_dir() && !Path::new(&input_spec).is_file() {
        eprintln!("Error: invalid --input {}", input_spec);
        std::process::exit(exitcode::CONFIG)
    }

    if Path::new(&input_spec).is_file() && !Path::new(&output_spec).is_file() {
        eprintln!("Error: --input <file spec> requires --output <file spec>");
        std::process::exit(exitcode::CONFIG)
    }

    if Path::new(&input_spec).is_dir() && !Path::new(&output_spec).is_dir() {
        eprintln!("Error: --input <dir spec> requires --output <dir spec>");
        std::process::exit(exitcode::CONFIG)
    }

    if !Path::new(&output_spec).is_dir() && !Path::new(&output_spec).is_file()
    {
        eprintln!("Error: invalid --output {}", output_spec);
        std::process::exit(exitcode::CONFIG)
    }

    if polling == true && processed_spec.is_empty() {
        eprintln!("Error: --processed_dir <dir spec> required when polling is active");
        std::process::exit(exitcode::CONFIG)
    }

    if !processed_spec.is_empty() && !Path::new(&processed_spec).is_dir() {
        eprintln!(
            "Error: --processed_dir {} is not a valid directory",
            processed_spec
        );
        std::process::exit(exitcode::CONFIG)
    }

    let _ = export(&input_spec, &output_spec, &processed_spec, polling, &format);
}
