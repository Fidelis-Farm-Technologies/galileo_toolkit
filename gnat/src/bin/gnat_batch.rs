/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */
use clap::Parser;
use gnat::core::batch::batch;
use std::path::Path;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    interval: u64,

    #[arg(long)]
    input: String,

    #[arg(long)]
    output: String,
}

fn main() {
    let args = Args::parse();
    let input_spec = args.input.clone();
    let output_spec = args.output.clone();
    let interval_spec = args.interval.clone();

    //
    // verify the combination of arguments are valid
    //
    if !Path::new(&input_spec).is_dir() {
        eprintln!("error: invalid --input directory {}", input_spec);
        std::process::exit(exitcode::CONFIG)
    }

    if !Path::new(&output_spec).is_dir() {
        eprintln!("error: invalid --output directory {}", output_spec);
        std::process::exit(exitcode::CONFIG)
    }

    if interval_spec <= 0 {
        eprintln!("error: invalid --interval value {}", interval_spec);
        std::process::exit(exitcode::CONFIG)
    }

    let _ = batch(interval_spec, input_spec, output_spec);
}
