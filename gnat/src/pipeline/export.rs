/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::pipeline::FIELDS;
use crate::utils::duckdb::{duckdb_open, duckdb_open_memory, duckdb_open_readonly};
use chrono::{DateTime, TimeZone, Utc};
use std::time::SystemTime;

use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::FileType;
use crate::pipeline::Interval;
use duckdb::Connection;
use std::io::Error;

pub struct ExportProcessor {
    pub command: String,
    pub input: String,
    pub output: String,
    pub pass: String,
    pub field_list: String,
    pub interval: Interval,
    pub extension: String,
    pub format: String,
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
        let interval = parse_interval(interval_string);
        let mut options = parse_options(options_string);
        options.entry("format").or_insert("json");
        options.entry("fields").or_insert("");
        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}={}]", command, key, value);
            }
        }

        let format = options.get("format").expect("expected format");
        let field_list = options.get("fields").expect("expected format");

        let list: Vec<String> = field_list.split(",").map(str::to_string).collect();
        for field in &list {
            if !FIELDS.contains(&field.as_str()) {
                let error_message = format!("invalid field: {}", field);
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

        Ok(Self {
            command: command.to_string(),
            input: input.to_string(),
            output: output.to_string(),
            pass: pass.to_string(),
            field_list: field_list.to_string(),
            interval: interval,
            extension: extension_string.to_string(),
            format: format.to_string(),
        })
    }
}
impl FileProcessor for ExportProcessor {
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
    fn get_file_extension(&self) -> &String {
        &self.extension
    }

    fn socket(&mut self) -> Result<(), Error> {
        Err(Error::other("socket function unsupported"))
    }
    fn delete_files(&self) -> bool {
        true
    }
    fn process(&mut self, file_list: &Vec<String>, _schema_type: FileType) -> Result<(), Error> {
        let conn = duckdb_open_memory(2);

        let mut parquet_list = String::from("[");
        for file in file_list.clone().into_iter() {
            parquet_list.push('\'');
            parquet_list.push_str(&file);
            parquet_list.push_str("',");
        }
        parquet_list.push(']');

        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        let output_file = format!("{}/gnat-{}-{}", self.output, self.command, rfc3339_name);

        let sql_command: String;
        match self.format.as_str() {
            "csv" => {
                sql_command = format!(
                    "COPY (SELECT * FROM read_parquet({}) TO '{}.csv' (HEADER, DELIMITER ',');",
                    parquet_list, output_file
                );
            }
            "json" => {
                sql_command = format!(
                    "COPY (SELECT * FROM read_parquet({}) TO '{}.json';",
                    parquet_list, output_file
                );
            }
            _ => {
                sql_command = format!(
                    "COPY (SELECT * FROM read_parquet({}) TO '{}.json';",
                    parquet_list, output_file
                );
            }
        }

        conn.execute_batch(&sql_command).expect("execute_batch");
        println!("exported: {} => {}", parquet_list, output_file);

        Ok(())
    }
}
