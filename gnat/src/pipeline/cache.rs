/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025
 * Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::model::histogram::MD_FLOW_TABLE;
use crate::pipeline::check_parquet_stream;
use crate::pipeline::load_environment;
use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;

use crate::utils::duckdb::duckdb_open;

use crate::pipeline::Interval;
use crate::pipeline::StreamType;
use chrono::DateTime;
use chrono::Utc;
use duckdb::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Error;
use std::path::Path;

#[derive(Clone, Serialize, Deserialize)]
pub struct InputJsonStructure {
    input: String,
}

pub struct CacheProcessor {
    pub command: String,
    pub input_list: Vec<String>,
    pub output_list: Vec<String>,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
    pub retention: u16,
    pub db_conn: Connection,
}

impl CacheProcessor {
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
        options.entry("retention").or_insert("0");
        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}=>{}]", command, key, value);
            }
        }
        let retention = options
            .get("retention")
            .expect("expected retention")
            .parse::<u16>()
            .unwrap();
        let mut input_list = Vec::<String>::new();
        input_list.push(input.to_string());
        let mut output_list = Vec::<String>::new();
        output_list.push(output.to_string());

        let db_conn = duckdb_open(&output_list[0], 2);
        let _ = db_conn
            .execute_batch(MD_FLOW_TABLE)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        Ok(Self {
            command: command.to_string(),
            input_list: input_list,
            output_list: output_list,
            pass: pass.to_string(),
            interval: interval,
            extension: extension_string.to_string(),
            retention: retention,
            db_conn: db_conn,
        })
    }

    fn purge_old(&mut self) -> Result<(), Error> {
        let sql = format!(
            "DELETE FROM flow WHERE stime < now() - interval '{} days';",
            self.retention
        );
        self.db_conn
            .execute_batch(&sql)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        Ok(())
    }

    fn consume(&mut self, parquet_list: &str, output_list: &Vec<String>) -> Result<i64, Error> {
        let command = self.get_command().clone();
        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        // Sanitize rfc3339_name for filesystem safety
        let safe_rfc3339 = rfc3339_name.replace(":", "-");
        let mut record_count: i64 = 0;

        let sql_count = format!("SELECT COUNT(*) FROM read_parquet({});", parquet_list);
        let mut stmt = self
            .db_conn
            .prepare(&sql_count)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        record_count = stmt
            .query_row([], |row| row.get(0))
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        if record_count > 0 {
            let sql = format!(
                "INSERT INTO flow SELECT * FROM read_parquet({});",
                parquet_list
            );
            self.db_conn.execute_batch(&sql).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;
            println!("{}: inserted {} flows", command, record_count);
        } else {
            println!("{}: no flows found", command);
        }

        Ok(record_count)
    }
}
impl FileProcessor for CacheProcessor {
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

        // Check if the parquet files are valid
        // If not, skip processing
        // This is a performance optimization to avoid processing invalid files
        // If the files are not valid, we will not be able to read them
        // and will end up with an empty table
        if let Ok(status) = check_parquet_stream(&parquet_list) {
            if status == false {
                eprintln!(
                    "{}: invalid stream of parquet files, skipping",
                    self.command
                );
                return Ok(());
            }
        }

        let record_count = self.consume(&parquet_list, &self.output_list.clone())?;
        if record_count > 0 {
            println!("{}: {} flows merged", self.command, record_count);
        } else {
            println!("{}: no flows merged", self.command);
        }

        if self.retention > 0 {
            self.purge_old()?;
        }
        Ok(())
    }
}
