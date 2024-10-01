/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */
use clap::Parser;
use crate::questdb::questdb_export;

mod questdb;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {

    #[arg(long)]
    input: String,

    #[arg(long)]
    host: String,

    #[arg(long)]
    ilp: Option<u16>,

    #[arg(long)]
    api: Option<u16>,

    #[arg(long)]
    retention: Option<u16>,

    #[arg(long)]
    processed: Option<String>,

    #[arg(long)]
    polling: Option<bool>,
}

fn main() {
    let args = Args::parse();

    let input_spec = args.input.clone();
    let host_spec = args.host.clone();
    let ilp_port = args.ilp.unwrap_or(9009);
    let api_port = args.api.unwrap_or(9000);
    let retention_days = args.retention.unwrap_or(7);
    let processed_spec = args.processed.unwrap_or(String::new()).clone();
    let poll = args.polling.unwrap_or(false).clone();

    questdb_export(&input_spec, &host_spec, ilp_port, api_port, &processed_spec, retention_days, poll);
}
