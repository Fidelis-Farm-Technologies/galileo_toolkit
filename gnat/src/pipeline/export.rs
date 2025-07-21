/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::pipeline::FIELDS;
use crate::utils::duckdb::duckdb_open_memory;
use chrono::{DateTime, Utc};

use crate::pipeline::check_parquet_stream;
use crate::pipeline::load_environment;
use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::Interval;
use crate::pipeline::StreamType;
use std::io::Error;

pub struct ExportProcessor {
    pub command: String,
    pub input_list: Vec<String>,
    pub output_list: Vec<String>,
    pub pass: String,
    pub field_list: String,
    pub interval: Interval,
    pub extension: String,
    pub format: String,
    pub filter: String,
}

impl ExportProcessor {
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
        options.entry("format").or_insert("json");
        options.entry("fields").or_insert("");
        options.entry("filter").or_insert("");
        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}=>{}]", command, key, value);
            }
        }

        let format = options.get("format").expect("expected format");
        let filter = options.get("filter").expect("expected filter");
        let field_list = options.get("fields").expect("expected format");

        let list: Vec<String> = field_list.split(",").map(str::to_string).collect();
        for field in &list {
            if !FIELDS.contains(&field.as_str()) {
                return Err(Error::other("field list contains invalid field"));
            }
        }

        // Validate the output directory
        if !output.is_empty() {
            let output_path = std::path::Path::new(output);
            if !output_path.exists() {
                return Err(Error::other("output directory does not exist"));
            }
        }

        let mut input_list = Vec::<String>::new();
        input_list.push(input.to_string());
        let mut output_list = Vec::<String>::new();
        output_list.push(output.to_string());
        Ok(Self {
            command: command.to_string(),
            input_list: input_list,
            output_list: output_list,
            pass: pass.to_string(),
            field_list: field_list.to_string(),
            interval: interval,
            extension: extension_string.to_string(),
            format: format.to_string(),
            filter: filter.to_string(),
        })
    }
}
impl FileProcessor for ExportProcessor {
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

        let conn = duckdb_open_memory(2);
        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        let output_file = format!(
            "{}/gnat-{}-{}",
            self.output_list[0], self.command, rfc3339_name
        );

        let where_filter = if !self.filter.is_empty() {
            format!(" WHERE {}", self.filter)
        } else {
            String::new()
        };

        let sql_command: String;
        match self.format.as_str() {
            "csv" => {
                sql_command = format!(
                    "COPY (SELECT * FROM read_parquet({}) {}) TO '{}.csv' (HEADER, DELIMITER ',');",
                    parquet_list, where_filter, output_file
                );
            }
            "json" => {
                sql_command = format!(
                    "COPY (SELECT * FROM read_parquet({}) {}) TO '{}.json';",
                    parquet_list, where_filter, output_file
                );
            }
            _ => {
                sql_command = format!(
                    "COPY (SELECT * FROM read_parquet({}) {}) TO '{}.json';",
                    parquet_list, where_filter, output_file
                );
            }
        }

        conn.execute_batch(&sql_command).expect("execute_batch");
        conn.close().expect("db close");
        println!("exported: {} => {}", parquet_list, output_file);

        Ok(())
    }
}
