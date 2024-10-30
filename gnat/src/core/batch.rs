/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use std::env;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;

use duckdb::Connection;

pub fn batch_files(output_spec: &String, tag: &String) {
    let conn = match Connection::open_in_memory() {
        Ok(s) => s,
        Err(e) => panic!("Error: open_in_memory() - {}", e),
    };

    let epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("UNIX_EPOCH");
    let tmp_filename = format!(".{}.parquet", epoch.as_millis());
    let final_filename = format!("{}/{}{}", output_spec, tag, tmp_filename);

    println!("Batch: merging...");

    let sql_command = format!(
        "COPY (SELECT * FROM read_parquet('.batch*.parquet')) TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
        tmp_filename
    );
    match conn.execute_batch(&sql_command) {
        Ok(c) => c,
        Err(e) => {
            panic!("Error: batching files {:?}", e);
        }
    };

    match fs::rename(tmp_filename.clone(), final_filename.clone()) {
        Ok(_s) => println!("Batch: generated {}", final_filename),
        Err(error) => panic!(
            "Error: renaming {} {}: {:?}",
            tmp_filename.clone(),
            final_filename.clone(),
            error
        ),
    };
}

pub fn batch(
    tag_spec: String,
    interval: u64,
    input_spec: String,
    output_spec: String,
) -> Result<(), std::io::Error> {
    println!("\tbatch interval: {} secs", interval);
    println!("\tinput spec: {}", input_spec);
    println!("\toutput spec: {}", output_spec);
    println!("\ttag spec: {}", tag_spec);

    let input_dir = Path::new(input_spec.as_str());
    if !env::set_current_dir(&input_dir).is_ok() {
        panic!(
            "Error: unable to set working directory to {}",
            input_dir.display()
        );
    }

    let time_interval = Duration::from_secs(interval);

    loop {
        let mut counter = 0;
        thread::sleep(time_interval);

        println!("Batch: scanning...");

        for entry in fs::read_dir(".").unwrap() {
            let file: fs::DirEntry = entry.unwrap();
            let file_name = String::from(file.file_name().to_string_lossy());

            if !file_name.starts_with(".") && file_name.ends_with(".parquet") {
                let new_name = format!(".batch-{}", file_name);
                fs::rename(file_name.clone(), new_name).unwrap();
                counter += 1;
            }
        }

        if counter > 0 {
            batch_files(&output_spec, &tag_spec);

            for entry in fs::read_dir(".").unwrap() {
                let file: fs::DirEntry = entry.unwrap();
                let file_name = String::from(file.file_name().to_string_lossy());

                if file_name.starts_with(".batch") && file_name.ends_with(".parquet") {
                    fs::remove_file(file_name).unwrap();
                }
            }
        }
    }
}
