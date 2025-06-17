/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::model::table::DistinctObservation;
use crate::utils::duckdb::{duckdb_open, duckdb_open_memory, duckdb_open_readonly};
use chrono::{DateTime, TimeZone, Utc};
use std::time::SystemTime;

use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::Interval;
use crate::pipeline::FileType;

use std::fs;
use std::io::Error;

pub struct SampleProcessor {
    pub command: String,
    pub input: String,
    pub output: String,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
    pub retention: u16,
    pub percent: f64,
}

impl SampleProcessor {
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
        options.entry("retention").or_insert("7");
        options.entry("percent").or_insert("20");
        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}={}]", command, key, value);
            }
        }
        let retention = options
            .get("retention")
            .expect("expected retention")
            .parse::<u16>()
            .unwrap();

        let percent = options
            .get("percent")
            .expect("expected percent")
            .parse::<u8>()
            .unwrap();

        Ok(Self {
            command: command.to_string(),
            input: input.to_string(),
            output: output.to_string(),
            pass: pass.to_string(),
            interval,
            extension: extension_string.to_string(),
            retention,
            percent: percent as f64,
        })
    }

    fn purge_old(&self) -> Result<(), Error> {
        let conn = duckdb_open_memory(2);
        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        let new_filename = format!("gnat-{}.{}.parquet", self.command, rfc3339_name.replace(":", "-"));
        let tmp_filename = format!("{}/.{}", self.output, new_filename);
        let final_filename = format!("{}/{}.parquet", self.output, new_filename);

        let mut file_list: Vec<String> = Vec::new();
        for entry in fs::read_dir(&self.output).map_err(|e| Error::new(std::io::ErrorKind::Other, format!("read_dir error: {}", e)))? {
            let file = entry.map_err(|e| Error::new(std::io::ErrorKind::Other, format!("file entry error: {}", e)))?;
            let file_name = file.file_name().to_string_lossy().to_string();
            if !file_name.starts_with('.') && file_name.ends_with(".parquet") {
                file_list.push(format!("{}/{}", self.output, file_name));
            }
        }

        let parquet_list = file_list
            .iter()
            .map(|file| format!("'{}'", file))
            .collect::<Vec<_>>()
            .join(",");
        let parquet_list = format!("[{}]", parquet_list);

        let sql_command = format!(
            "COPY (SELECT * FROM read_parquet({}) \n         WHERE (proto='tcp' OR proto='udp') AND (sfirstnonemptycnt > 0 OR dfirstnonemptycnt > 0) \n         AND date_trunc('day',stime) > date_add(date_trunc('day',stime), - INTERVAL {} DAY))\n         TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
            parquet_list, self.retention, tmp_filename
        );
        conn.execute_batch(&sql_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        for file in &file_list {
            fs::remove_file(file)
                .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("failed to remove file {}: {}", file, e)))?;
        }

        fs::rename(&tmp_filename, &final_filename)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("renaming error: {}", e)))?;
        println!("{}: purged old records.", self.command);
        Ok(())
    }

    fn generate_samples(&mut self, file_list: &Vec<String>) -> Result<(), Error> {
        let conn = duckdb_open_memory(2);
        let parquet_list = file_list
            .iter()
            .map(|file| format!("'{}'", file))
            .collect::<Vec<_>>()
            .join(",");
        let parquet_list = format!("[{}]", parquet_list);

        let sql_distinct_command = format!(
            "SELECT DISTINCT observe, dvlan, proto FROM read_parquet({}) WHERE proto='tcp' OR proto='udp' GROUP BY ALL ORDER BY ALL",
            parquet_list
        );
        let mut stmt = conn.prepare(&sql_distinct_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("sql prepare error: {}", e)))?;
        let record_iter = stmt
            .query_map([], |row| {
                Ok(DistinctObservation {
                    observe: row.get(0).expect("missing value"),
                    vlan: row.get(1).expect("missing value"),
                    proto: row.get(2).expect("missing value"),
                })
            })
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("query map error: {}", e)))?;

        for record in record_iter {
            let record = record.map_err(|e| Error::new(std::io::ErrorKind::Other, format!("record error: {}", e)))?;
            println!(
                "{}: sampling [{}/{}/{}] {}%",
                self.command, record.observe, record.vlan, record.proto, self.percent
            );
            let current_utc: DateTime<Utc> = Utc::now();
            let rfc3339_name: String = current_utc.to_rfc3339();
            let new_filename = format!(
                "gnat-{}-{}-{}-{}.{}.parquet",
                self.command, record.observe, record.vlan, record.proto, rfc3339_name.replace(":", "-")
            );
            let tmp_filename = format!("{}/.{}", self.output, new_filename);
            let final_filename = format!("{}/{}.parquet", self.output, new_filename);
            let sql_command = format!(
                "COPY (SELECT * FROM read_parquet({}) \n                 WHERE observe='{}' AND dvlan = {} AND proto='{}' AND (sfirstnonemptycnt > 0 OR dfirstnonemptycnt > 0) USING SAMPLE {}%)\n                 TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
                 parquet_list, record.observe, record.vlan, record.proto, self.percent, tmp_filename);
            conn.execute_batch(&sql_command)
                .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
            fs::rename(&tmp_filename, &final_filename)
                .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("renaming error: {}", e)))?;
        }
        println!("{}: sampled new records.", self.command);
        Ok(())
    }
}

impl FileProcessor for SampleProcessor {
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
    fn process(&mut self, file_list: &Vec<String>,  _schema_type: FileType) -> Result<(), Error> {
        self.generate_samples(file_list)?;
        self.purge_old()?;
        Ok(())
    }
}
