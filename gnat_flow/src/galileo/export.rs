/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

//use duckdb::arrow::datatypes::ArrowNativeType;
//use questdb::ingress::{Buffer, Sender, TimestampNanos};

use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use duckdb::Connection;

pub fn export_file(input_spec: &String, output_spec: &String, format: &String) -> bool {
    let conn = match Connection::open_in_memory() {
        Ok(s) => s,
        Err(e) => panic!("error:  open_in_memory() - {}", e),
    };

    let sql_command: String;
    match format.as_str() {
        "csv" => {
            sql_command = format!(
                "COPY (SELECT * FROM '{}') TO '{}.csv' (HEADER, DELIMITER ',');",
                input_spec, output_spec
            );
            println!("exported: {} => {}", input_spec, output_spec);
        }
        "json" => {
            sql_command = format!(
                "COPY (SELECT * FROM '{}') TO '{}';",
                input_spec, output_spec
            );
        }
        _ => {
            // default is JSON
            sql_command = format!(
                "COPY (SELECT * FROM '{}') TO '{}';",
                input_spec, output_spec
            );
            println!("exported: {} => {}", input_spec, output_spec);
        }
    }

    match conn.execute_batch(&sql_command) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: exporting file {} -- {:?}", input_spec, e);
            return false;
        }
    };

    true
}

pub fn export(
    input_spec: &String,
    output_spec: &String,
    processed_spec: &String,
    polling: bool,
    format: &String,
) {
    if PathBuf::from(input_spec.clone()).is_dir() {
        println!("\tinput spec: {}", input_spec);
        println!("\toutput spec: {}", output_spec);
        println!("\tprocessed spec: {}", processed_spec);
        println!("\texport format: {}", format);
        println!("\tpolling: {}", polling);

        let poll_interval = Duration::from_millis(1000);
        println!("export scanner: running [{}]", input_spec);
        loop {
            let mut counter = 0;
            let directory = match fs::read_dir(input_spec) {
                Ok(d) => d,
                Err(e) => panic!("error: reading directory {} -- {:?}", input_spec, e),
            };

            for entry in directory {
                let file = entry.unwrap();
                let file_name = String::from(file.file_name().to_string_lossy());
                let src_path = String::from(file.path().to_string_lossy());

                if let Ok(metadata) = file.metadata() {
                    // don't process zero length files
                    let error_file = format!(
                        "{}/{}.error",
                        processed_spec,
                        file.file_name().to_string_lossy()
                    );
                    if metadata.len() <= 0 {
                        let _ = fs::rename(file.path(), error_file);
                        continue;
                    }
                }

                if !file_name.starts_with(".") && file_name.ends_with(".parquet") {
                    let dst_spec;
                    if format == "questdb" {
                        dst_spec = output_spec.clone();
                    } else {
                        dst_spec = format!("{}/{}.{}", output_spec, file_name, format);
                    }

                    if export_file(&src_path, &dst_spec, format) {
                        if !processed_spec.is_empty() {
                            let processed_path =
                                format!("{}/{}", &processed_spec, file_name.to_string());

                            match fs::rename(src_path.clone(), processed_path.clone()) {
                                Ok(c) => c,
                                Err(e) => panic!(
                                    "error: moving {} -> {}: {:?}",
                                    src_path, processed_path, e
                                ),
                            };
                        }
                    } else {
                        eprintln!("error: exporting {} => {}", src_path, dst_spec);
                        std::process::exit(exitcode::PROTOCOL);
                    }
                    counter += 1;
                }
            }
            if !polling {
                break;
            }
            if counter == 0 {
                thread::sleep(poll_interval);
            }
        }
    } else {
        export_file(input_spec, output_spec, format);
    }
}
