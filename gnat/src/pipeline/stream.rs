/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::model::table::MemFlowRecord;
use crate::pipeline::load_environment;
use crate::pipeline::StreamType;
use crate::utils::duckdb::{duckdb_open, duckdb_open_memory, duckdb_open_readonly};
use chrono::{DateTime, TimeZone, Utc};
use duckdb::Connection;
use serde::{Deserialize, Serialize};

use duckdb::{params, Appender, DropBehavior};
use std::fs;
use std::process;

use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::FileType;
use crate::pipeline::Interval;

use std::io::Error;

#[derive(Clone, Serialize, Deserialize)]
pub struct StreamStructure {
    tag: String,
    filter: String,
    path: String,
}

pub struct StreamProcess {
    pub command: String,
    pub input: String,
    pub output: String,
    pub stream_list: Vec<StreamStructure>,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
}

impl StreamProcess {
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
        let mut options = parse_options(options_string);

        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}={}]", command, key, value);
            }
        }

        let stream_list = Self::load_stream_list(&output).map_err(|e| {
            Error::new(
                std::io::ErrorKind::Other,
                format!("failed to load stream list: {}", e),
            )
        })?;

        if stream_list.is_empty() {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "stream list cannot be empty",
            ));
        }

        Ok(Self {
            command: command.to_string(),
            input: input.to_string(),
            output: output.to_string(),
            stream_list: stream_list,
            pass: pass.to_string(),
            interval: interval,
            extension: extension_string.to_string(),
        })
    }

    fn load_stream_list(stream_spec: &str) -> Result<Vec<StreamStructure>, Error> {
        println!("Loading stream filters...");
        let json_data: String = fs::read_to_string(stream_spec).expect("unable to read JSON file");
        let stream_list: Vec<StreamStructure> =
            serde_json::from_str(&json_data).expect("failed to parse tag file");
        for stream in &stream_list {
            if stream.filter.is_empty() {
                return Err(Error::other("stream filter cannot be empty"));
            }
            if stream.path.is_empty() {
                return Err(Error::other("stream path cannot be empty"));
            }
            if !fs::metadata(&stream.path).is_ok() {
                return Err(Error::other(format!(
                    "stream path does not exist: {}",
                    stream.path
                )));
            }
            println!(
                "stream: {} | filter: {} | path: {}",
                stream.tag, stream.filter, stream.path
            );
        }
        println!(".done.");
        Ok(stream_list)
    }
}
impl FileProcessor for StreamProcess {
    fn get_command(&self) -> &String {
        &self.command
    }
    fn get_input(&self) -> &String {
        &self.input
    }
    fn get_output(&self) -> &String {
        &self.output
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

        let mut count = 0;
        for stream in &self.stream_list {
            println!(
                "{}: processing stream [{} | {}]",
                self.command, stream.tag, stream.path
            );
            let tmp_filename = format!(".gnat-{}-{}.{}.parquet", self.command, safe_rfc3339, count);
            let final_filename =
                format!("{}/{}", stream.path, tmp_filename.trim_start_matches('.'));
            let mut sql_command = String::new();
            if stream.filter == "*" {
                // If filter is wildcard, then just copy the parquet files directly
                sql_command = format!(
                    "CREATE OR REPLACE TABLE stream AS SELECT * FROM read_parquet({});
                     UPDATE stream SET tag = list_concat(tag, ['{}']) WHERE tag IS NULL OR NOT list_has_any(tag,['{}']);
                     COPY stream TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
                    parquet_list, stream.tag, stream.tag, tmp_filename
                );
            } else {
                sql_command = format!(
                    "CREATE OR REPLACE TABLE stream AS SELECT * FROM read_parquet({}) WHERE {};
                     UPDATE stream SET tag = list_concat(tag, ['{}']) WHERE tag IS NULL OR NOT list_has_any(tag,['{}']);
                     COPY stream TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
                    parquet_list, stream.filter, stream.tag, stream.tag, tmp_filename
                );
            }

            let _ = conn.execute_batch(&sql_command).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;

            if fs::exists(&tmp_filename).expect("check tmp file existence") {
                fs::rename(&tmp_filename, &final_filename).map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("File rename error: {}", e),
                    )
                })?;
            }
            count += 1;
        }

        let _ = conn.close();

        Ok(())
    }
}
