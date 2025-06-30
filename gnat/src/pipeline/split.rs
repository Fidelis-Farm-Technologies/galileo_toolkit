/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::pipeline::load_environment;
use crate::pipeline::StreamType;
use crate::utils::duckdb::duckdb_open_memory;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;

use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::Interval;
use duckdb::params;
use std::io::Error;

#[derive(Clone, Serialize, Deserialize)]
pub struct FilterStructure {
    proto: String,
    path: String,
}

pub struct SplitProcessor {
    pub command: String,
    pub input_list: Vec<String>,
    pub output_list: Vec<String>,
    pub split_list: Vec<FilterStructure>,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
}

impl SplitProcessor {
    pub fn new(
        command: &str,
        input: &str,
        output: &str,
        pass: &str,
        interval_string: &str,
        extension_string: &str,
        options_string: &str,
    ) -> Result<Self, Error> {
        let _ = load_environment();
        let interval = parse_interval(interval_string);
        let options = parse_options(options_string);

        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}={}]", command, key, value);
            }
        }

        let split_list = Self::load_split_list(&output).map_err(|e| {
            Error::new(
                std::io::ErrorKind::Other,
                format!("failed to load split list: {}", e),
            )
        })?;

        if split_list.is_empty() {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "split list cannot be empty",
            ));
        }

        let mut input_list = Vec::<String>::new();
        input_list.push(input.to_string());

        let mut output_list = Vec::<String>::new();
        for split in &split_list {
            output_list.push(split.path.clone());
        }
        Ok(Self {
            command: command.to_string(),
            input_list: input_list,
            output_list: output_list,
            split_list: split_list,
            pass: pass.to_string(),
            interval: interval,
            extension: extension_string.to_string(),
        })
    }

    fn load_split_list(split_spec: &str) -> Result<Vec<FilterStructure>, Error> {
        //println!("Loading split filters...");
        let json_data: String = fs::read_to_string(split_spec).expect("unable to read JSON file");
        let split_list: Vec<FilterStructure> =
            serde_json::from_str(&json_data).expect("failed to parse JSON file");

        for split in &split_list {
            if split.proto.is_empty() {
                return Err(Error::other("split filter cannot be empty"));
            }
            if split.path.is_empty() {
                return Err(Error::other("split path cannot be empty"));
            }
            if !fs::metadata(&split.path).is_ok() {
                return Err(Error::other(format!(
                    "split path does not exist: {}",
                    split.path
                )));
            }

            println!("\tsplit: [{} =>  {}]", split.proto, split.path);
        }
        //println!(".done.");
        Ok(split_list)
    }
}
impl FileProcessor for SplitProcessor {
    fn get_command(&self) -> &String {
        &self.command
    }
    fn get_input(&self, input_list: &mut Vec<String>) -> Result<(), Error> {
        *input_list = self.input_list.clone();
        Ok(())
    }
    fn get_output(&self, output_list: &mut Vec<String>) -> Result<(), Error> {
        *output_list = self.output_list.clone();
        Ok(())
    }
    fn get_pass(&self) -> &String {
        &self.pass
    }
    fn get_interval(&self) -> &Interval {
        &self.interval
    }
    fn get_stream_id(&self) -> u32 {
        StreamType::ADHOC as u32
    }
    fn get_file_extension(&self) -> &String {
        &self.extension
    }
    fn socket(&mut self) -> Result<(), Error> {
        Err(Error::other("socket function unsupported"))
    }
    fn delete_files(&self) -> bool {
        true
    }
    fn process(&mut self, file_list: &Vec<String>) -> Result<(), Error> {
        // Use iterator and join for file list formatting
        let parquet_list = file_list
            .iter()
            .map(|file| format!("'{}'", file))
            .collect::<Vec<_>>()
            .join(",");
        let parquet_list = format!("[{}]", parquet_list);

        let conn = duckdb_open_memory(2);

        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        // Sanitize rfc3339_name for filesystem safety
        let safe_rfc3339 = rfc3339_name.replace(":", "-");

        for split in &self.split_list {
            println!(
                "{}: processing split [{} => {}]",
                self.command, split.proto, split.path
            );
            let tmp_filename = format!(
                "{}/.gnat-{}-{}.{}.parquet",
                split.path, self.command, safe_rfc3339, split.proto
            );
            let final_filename = format!(
                "{}/gnat-{}-{}.{}.parquet",
                split.path, self.command, safe_rfc3339, split.proto
            );

            let sql = format!(
                "CREATE OR REPLACE TABLE split AS SELECT * FROM read_parquet({}) WHERE proto='{}';",
                parquet_list, split.proto
            );

            match conn.execute(&sql, params![]) {
                Ok(count) => {
                    if count > 0 {
                        let sql_copy = format!("COPY split TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);", tmp_filename);
                        let _ = conn.execute_batch(&sql_copy).map_err(|e| {
                            Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                        })?;
                        fs::rename(&tmp_filename, &final_filename)?;
                    }
                }
                Err(err) => {
                    return Err(Error::new(
                        std::io::ErrorKind::Other,
                        format!("DuckDB error: {}", err),
                    ))
                }
            }
        }

        let _ = conn.close();

        Ok(())
    }
}
