/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use clap::Parser;
use gnat::pipeline::rule::RuleProcessor;
use gnat::pipeline::FileProcessor;
use std::error::Error;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    input: String,

    #[arg(long)]
    output: String,

    #[arg(long)]
    pass: Option<String>,

    #[arg(long)]
    options: Option<String>,

    #[arg(long)]
    interval: Option<String>,   
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let mut rule_processor = RuleProcessor::new(
        "rule",
        &args.input,
        &args.output,
        &args.pass.clone().unwrap_or(String::new()),
        &args.interval.clone().unwrap_or(String::from("second")),
        ".parquet",
        &args.options.clone().unwrap_or(String::new()),
    )?;

    rule_processor.run()?;

    Ok(())
}
