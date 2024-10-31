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
    minutes: Option<u32>,

    #[arg(long)]
    input: String,

    #[arg(long)]
    output: String,

    #[arg(long)]
    tag: Option<String>,
}

fn main() {
    let args = Args::parse();
    let input_spec = args.input.clone();
    let output_spec = args.output.clone();
    let minutes_spec = args.minutes.unwrap_or(1).clone();
    let tag_spec = args.tag.unwrap_or("gnat".to_string()).clone();
    //
    // verify the combination of arguments are valid
    //
    if !Path::new(&input_spec).is_dir() {
        eprintln!("Error: invalid --input directory {}", input_spec);
        std::process::exit(exitcode::CONFIG)
    }

    if !Path::new(&output_spec).is_dir() {
        eprintln!("Error: invalid --output directory {}", output_spec);
        std::process::exit(exitcode::CONFIG)
    }

    if minutes_spec <= 0 {
        eprintln!("Error: invalid --interval value {}", minutes_spec);
        std::process::exit(exitcode::CONFIG)
    }

    let _ = batch(tag_spec, minutes_spec, input_spec, output_spec);
}
