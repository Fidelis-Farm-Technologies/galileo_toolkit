/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */
use clap::Parser;

use chrono::offset::Utc;
use std::env;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

use duckdb::Connection;
use questdb::ingress::Sender;

use gnat_db::table::appid::AppIdTable;
use gnat_db::table::asn::AsnTable;
use gnat_db::table::bytes::BytesTable;
use gnat_db::table::country::CountryTable;
use gnat_db::table::dns::DnsTable;
use gnat_db::table::doh::DohTable;
use gnat_db::table::flow::FlowTable;
use gnat_db::table::packets::PacketsTable;
use gnat_db::table::proto::ProtoTable;
use gnat_db::table::ssh::SshTable;
use gnat_db::table::quic::QuicTable;
use gnat_db::TableTrait;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    input: String,

    #[arg(long)]
    polling: Option<u64>,

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
    tables: Option<String>,
}

fn questdb_insert(
    polling_interval: u64,
    input_spec: &String,
    host_spec: &String,
    ilp_port: u16,
    api_port: u16,
    processed_spec: &String,
    retention_days: u16,
    table_spec: &String,
) {
    println!("\tinput spec: {}", input_spec);
    println!("\tprocessed spec: {}", processed_spec);
    println!("\tdb spec: {}", host_spec);
    println!("\tilp port: {}", ilp_port);
    println!("\tapi port: {}", api_port);
    println!("\tretention days: {}", retention_days);
    println!("\tpolling interval: {}", polling_interval);
    println!("\ttable spec: {}", table_spec);
    //
    // change working directory
    //
    let input_dir = Path::new(input_spec.as_str());
    if !env::set_current_dir(&input_dir).is_ok() {
        panic!(
            "error: unable to set working directory to {}",
            input_dir.display()
        );
    }

    //
    // instantiate and load table objects
    //
    let appid: AppIdTable = AppIdTable {
        table_name: "appid",
    };
    let asn: AsnTable = AsnTable { table_name: "asn" };
    let bytes: BytesTable = BytesTable {
        table_name: "bytes",
    };
    let country: CountryTable = CountryTable {
        table_name: "country",
    };
    let dns: DnsTable = DnsTable { table_name: "dns" };
    let doh: DohTable = DohTable { table_name: "doh" };    
    let flow: FlowTable = FlowTable { table_name: "flow" };
    let packets: PacketsTable = PacketsTable {
        table_name: "packets",
    };
    let proto: ProtoTable = ProtoTable {
        table_name: "proto",
    };
    let quic: QuicTable = QuicTable {
        table_name: "quic",
    };    
    let ssh: SshTable = SshTable {
        table_name: "ssh",
    };
    let mut table_list: Vec<&dyn TableTrait> = Vec::new();
    table_list.push(&appid);
    table_list.push(&asn);
    table_list.push(&bytes);
    table_list.push(&country);
    table_list.push(&dns);
    table_list.push(&doh);    
    table_list.push(&flow);
    table_list.push(&packets);
    table_list.push(&proto);
    table_list.push(&ssh);
    table_list.push(&quic);    
    //
    // instantiate questdb connection
    //
    let api_url = format!("http://{}:{}/exec", host_spec, api_port);
    let Ok(mut sink) = Sender::from_conf(format!("tcp::addr={}:{};", host_spec, ilp_port)) else {
        panic!("Error: connectiong to QuestDB");
    };

    //
    // CREATE tables if they don't exist
    //
    for table in table_list.iter() {
        table.create(&api_url);
    }

    let mut last = Utc::now();
    let sleep_interval = Duration::from_secs(polling_interval);
    println!("File scanner: running [{}]", input_spec);
    loop {
        //
        // is it time to drop older days (partitions)?
        //
        let now = Utc::now();
        let duration = now.signed_duration_since(last);
        if duration.num_hours() > 0 {
            last = now;
            //
            // DROP partitions, check every hour
            //
            for table in table_list.iter() {
                table.drop(&api_url, retention_days);
            }
        }

        let directory = match fs::read_dir(input_spec) {
            Ok(d) => d,
            Err(e) => panic!("Error: reading directory {} -- {:?}", input_spec, e),
        };
        let mut counter = 0;
        for entry in directory {
            let file = entry.unwrap();
            let filename = String::from(file.file_name().to_string_lossy());
            let src_path = String::from(file.path().to_string_lossy());

            if let Ok(metadata) = file.metadata() {
                if metadata.len() <= 0 {
                    // skip file
                    continue;
                }
            }

            if filename.starts_with("gnat") && filename.ends_with(".parquet") {
                // rename file so it isn't clobbered
                let tmp_filename = format!(".{}", filename.clone());
                fs::rename(filename.clone(), tmp_filename.clone()).unwrap();

                let source = match Connection::open_in_memory() {
                    Ok(s) => s,
                    Err(e) => panic!("error:  open_in_memory() - {}", e),
                };
                let sql_command = format!(
                    "CREATE TABLE memtable AS SELECT * FROM '{}';",
                    tmp_filename.clone()
                );

                match source.execute_batch(&sql_command) {
                    Ok(c) => c,
                    Err(e) => {
                        panic!("error: creating table from file {} - {:?}", tmp_filename, e);
                    }
                };
                //
                // INSERT new data
                //
                for table in table_list.iter() {
                    table.insert(&mut sink, &source);
                }
                source.close().unwrap();

                //
                // move or remove the file
                //
                if !processed_spec.is_empty() {
                    let processed_path = format!("{}/{}", &processed_spec, filename.to_string());

                    match fs::rename(src_path.clone(), processed_path.clone()) {
                        Ok(c) => c,
                        Err(e) => {
                            panic!("Error: moving {} -> {}: {:?}", src_path, processed_path, e)
                        }
                    };
                } else {
                    fs::remove_file(src_path.clone()).unwrap();
                }
                counter += 1;
            }
        }
        if counter == 0 {
            thread::sleep(sleep_interval);
        }
        if polling_interval == 0 {
            // one-shot scan
            break;
        }
    }
}

fn main() {
    let args = Args::parse();

    let polling_interval: u64 = args.polling.unwrap_or(0);
    let input_spec: String = args.input.clone();
    let host_spec: String = args.host.clone();
    let ilp_port: u16 = args.ilp.unwrap_or(9009);
    let api_port: u16 = args.api.unwrap_or(9000);
    let retention_days: u16 = args.retention.unwrap_or(7);
    let processed_spec: String = args.processed.unwrap_or(String::new()).clone();
    let tables_spec: String = args.tables.unwrap_or(String::from("all")).clone();

    if !Path::new(&input_spec).is_dir() {
        eprintln!("error: invalid --input directory {}", input_spec);
        std::process::exit(exitcode::CONFIG)
    }

    questdb_insert(
        polling_interval,
        &input_spec,
        &host_spec,
        ilp_port,
        api_port,
        &processed_spec,
        retention_days,
        &tables_spec,
    );
}
