/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::model::histogram::MINIMUM_DAYS;
use crate::model::table::DistinctObservation;
use crate::pipeline::load_environment;
use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;

use crate::pipeline::check_parquet_stream;
use crate::pipeline::FileProcessor;

use crate::pipeline::Interval;
use crate::pipeline::StreamType;
use crate::utils::duckdb::duckdb_open_memory;
use chrono::{DateTime, Utc};

use std::fs;
use std::io::Error;

pub struct SampleProcessor {
    pub command: String,
    pub input_list: Vec<String>,
    pub output_list: Vec<String>,
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
        let _ = load_environment();
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

        let mut input_list = Vec::<String>::new();
        input_list.push(input.to_string());
        let mut output_list = Vec::<String>::new();
        output_list.push(output.to_string());
        Ok(Self {
            command: command.to_string(),
            input_list: input_list,
            output_list: output_list,
            pass: pass.to_string(),
            interval: interval,
            extension: extension_string.to_string(),
            retention,
            percent: percent as f64,
        })
    }

    fn purge_old(&self) -> Result<(), Error> {
        let conn = duckdb_open_memory(2);
        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        let new_filename = format!(
            "gnat-{}.{}.parquet",
            self.command,
            rfc3339_name.replace(":", "-")
        );
        let tmp_filename = format!("{}/.{}", self.output_list[0], new_filename);
        let final_filename = format!("{}/{}.parquet", self.output_list[0], new_filename);

        let mut file_list: Vec<String> = Vec::new();
        for entry in fs::read_dir(&self.output_list[0])
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("read_dir error: {}", e)))?
        {
            let file = entry.map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("file entry error: {}", e),
                )
            })?;
            let file_name = file.file_name().to_string_lossy().to_string();
            if !file_name.starts_with('.') && file_name.ends_with(".parquet") {
                file_list.push(format!("{}/{}", self.output_list[0], file_name));
            }
        }

        if file_list.is_empty() {
            println!("{}: no files to purge", self.command);
            return Ok(());
        }
        
        let parquet_list = file_list
            .iter()
            .map(|file| format!("'{}'", file))
            .collect::<Vec<_>>()
            .join(",");
        let parquet_list = format!("[{}]", parquet_list);

        let sql_command = format!(
            "COPY (SELECT * FROM read_parquet({})
                   WHERE date_trunc('day',stime) > date_add(date_trunc('day',stime), - INTERVAL {} DAY))
                TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
            parquet_list, self.retention, tmp_filename
        );
        //println!("{}: {}", self.command,sql_command);
        conn.execute_batch(&sql_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        for file in &file_list {
            fs::remove_file(file).map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to remove file {}: {}", file, e),
                )
            })?;
        }

        fs::rename(&tmp_filename, &final_filename)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("renaming error: {}", e)))?;
        println!("{}: purged old records.", self.command);
        Ok(())
    }

    fn generate_samples(&mut self, file_list: &Vec<String>) -> Result<(), Error> {
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
        let conn = duckdb_open_memory(2);
        // check the number of days in the dataset
        /*
        {
            println!("{}: checking dataset duration...", self.command);
            // Use date_diff to calculate the number of days between the first and last timestamps
            let sql_days_command = format!(
                "SELECT date_diff('day',first,last)
                 FROM (SELECT MIN(stime) AS first, MAX(stime) AS last
                 FROM read_parquet({}));",
                parquet_list
            );
            let mut stmt = conn.prepare(&sql_days_command).map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("DuckDB prepare error: {}", e),
                )
            })?;
            let days = stmt
                .query_row([], |row| Ok(row.get::<_, u32>(0).expect("missing version")))
                .expect("missing days");
            println!("{}: {} days of data", self.command, days);
            if days < MINIMUM_DAYS {
                println!("{}: not enough data to sample, skipping", self.command);
                return Ok(());
            }
        }
        */

        let sql_command = format!(
            "CREATE TABLE flow AS SELECT * FROM read_parquet({});",
            parquet_list
        );
        conn.execute_batch(&sql_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        let mut stmt = conn
            .prepare("SELECT DISTINCT observe, dvlan, proto FROM flow GROUP BY ALL ORDER BY ALL")
            .map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("sql prepare error: {}", e),
                )
            })?;
        let record_iter = stmt
            .query_map([], |row| {
                Ok(DistinctObservation {
                    observe: row.get(0).expect("missing value"),
                    vlan: row.get(1).expect("missing value"),
                    proto: row.get(2).expect("missing value"),
                })
            })
            .map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("query map error: {}", e))
            })?;

        for record in record_iter {
            let record = record.map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("record error: {}", e))
            })?;
            println!(
                "{}: sampling [{}/{}/{}] {}%",
                self.command, record.observe, record.vlan, record.proto, self.percent
            );
            let current_utc: DateTime<Utc> = Utc::now();
            let rfc3339_name: String = current_utc.to_rfc3339();
            let new_filename = format!(
                "gnat-{}-{}-{}-{}.{}.parquet",
                self.command,
                record.observe,
                record.vlan,
                record.proto,
                rfc3339_name.replace(":", "-")
            );
            let tmp_filename = format!("{}/.{}", self.output_list[0], new_filename);
            let final_filename = format!("{}/{}.parquet", self.output_list[0], new_filename);
            let sql_command = format!(
                "COPY (SELECT * FROM flow
                 WHERE observe='{}' 
                   AND dvlan = {} AND proto='{}'                   
                   AND TRIGGER = 0
                 USING SAMPLE {}%)
                 TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
                record.observe, record.vlan, record.proto, self.percent, tmp_filename
            );
            conn.execute_batch(&sql_command).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;
            fs::rename(&tmp_filename, &final_filename).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("renaming error: {}", e))
            })?;
        }
        println!("{}: sampled records.", self.command);
        Ok(())
    }
}

impl FileProcessor for SampleProcessor {
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
        StreamType::IPFIX as u32
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
        self.generate_samples(file_list)?;
        self.purge_old()?;
        Ok(())
    }
}
