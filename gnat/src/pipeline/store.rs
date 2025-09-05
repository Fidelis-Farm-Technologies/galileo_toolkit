/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::model::histogram::MD_FLOW_TABLE;
use crate::pipeline::load_environment;
use crate::pipeline::use_motherduck;

use crate::pipeline::check_parquet_stream;
use crate::pipeline::StorageType;
use crate::pipeline::StreamType;
use crate::utils::duckdb::{duckdb_open, duckdb_open_memory};
use duckdb::Connection;
use std::env;

use chrono::DateTime;
use chrono::Utc;

use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::Interval;
use std::io::Error;

#[derive(Debug)]
struct DistinctDay {
    year: i32,
    month: i32,
    day: i32,
}

pub struct StoreProcessor {
    pub command: String,
    pub input_list: Vec<String>,
    pub output_list: Vec<String>,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
    pub storage_type: StorageType,
    pub db_conn: Connection,
    pub filter: String,
}

impl StoreProcessor {
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
        let storage_type = Self::get_storage_type(output)?;
        let mut options = parse_options(options_string);
        options.entry("filter").or_insert("");

        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}=>{}]", command, key, value);
            }
        }

        let mut filter_type = options.get("filter").expect("expected filter type").to_string();        
        if !filter_type.is_empty() {
            if filter_type == "trigger" {
                filter_type = String::from("(trigger > 0)");
                println!("{}: storing triggered records", command);
            } else if filter_type == "severe" {
                filter_type = String::from("(hbos_severity > 0)");
                println!("{}: storing severe records", command);
            }
            else {
                return Err(Error::other("unsupported filter type"));
            }
        }

        let mut db_conn = duckdb_open_memory(1)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        if storage_type == StorageType::MOTHERDUCK {
            if use_motherduck(output).expect("motherduck env") {
                db_conn = duckdb_open(output, 1).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;
                let _ = db_conn.execute_batch(MD_FLOW_TABLE).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;
                println!("{}: connection established with {}", command, output);
            } else {
                return Err(Error::other("motherduck is not enabled"));
            }
        } else if storage_type == StorageType::S3 {
            let s3_endpoint = env::var("S3_ENDPOINT")
                .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("S3 error: {}", e)))?;
            let s3_access_key_id = env::var("S3_ACCESS_KEY_ID")
                .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("S3 error: {}", e)))?;
            let s3_secret_access_key = env::var("S3_SECRET_ACCESS_KEY")
                .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("S3 error: {}", e)))?;
            let s3_region = env::var("S3_REGION").unwrap_or("US".to_string());
            let s3_url_style = env::var("S3_URL_STYLE").unwrap_or("path".to_string());

            //
            // load secret credentials
            //
            println!("{}: S3 uploader initializing...", command);
            let sql_secret = format!(
                "CREATE SECRET secret (
                 TYPE S3, KEY_ID '{}', 
                 SECRET '{}', 
                 REGION '{}', 
                 ENDPOINT '{}', 
                 URL_STYLE '{}');",
                s3_access_key_id, s3_secret_access_key, s3_region, s3_endpoint, s3_url_style
            );
            db_conn.execute_batch(&sql_secret).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;
        } else {
            // For local storage, we can use an in-memory connection
            println!("{}: using local storage", command);
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
            interval: interval,
            extension: extension_string.to_string(),
            storage_type: storage_type,
            db_conn: db_conn,
            filter: filter_type,
        })
    }

    pub fn get_storage_type(output: &str) -> Result<StorageType, Error> {
        if output.starts_with("md:") {
            if env::var("motherduck_token").is_ok() {
                return Ok(StorageType::MOTHERDUCK);
            }
        } else if output.starts_with("s3:") {
            if !env::var("S3_ENDPOINT").is_ok() {
                return Err(Error::other("missing S3 endpoint"));
            }
            if !env::var("S3_ACCESS_KEY_ID").is_ok() {
                return Err(Error::other("missing S3 access key ID"));
            }
            if !env::var("S3_SECRET_ACCESS_KEY").is_ok() {
                return Err(Error::other("missing S3 secret access key"));
            }
            return Ok(StorageType::S3);
        } else if output.starts_with("/") {
            return Ok(StorageType::LOCAL);
        }
        return Err(Error::other("unsupported storage type"));
    }

    fn upload_to_motherduck(&mut self, file_list: &Vec<String>) -> Result<(), Error> {
        println!("{}: sending to motherduck...", self.command);
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
        for parquet_file in file_list.clone().into_iter() {
            let mut sql_export = String::new();
            if self.filter.is_empty() {
                sql_export = format!(
                    "INSERT INTO flow SELECT * FROM read_parquet('{}');",
                    parquet_file
                );
            } else {
                sql_export = format!(
                    "INSERT INTO flow SELECT * FROM read_parquet('{}') WHERE {};",
                    parquet_file, self.filter
                );
            }
            let _ = self.db_conn.execute_batch(&sql_export).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;
        }
        println!("{}: done.", self.command);
        Ok(())
    }

    fn upload_to_s3(&mut self, file_list: &Vec<String>) -> Result<(), Error> {
        println!("{}: processing records for S3 storage...", self.command);
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

        // Get current time for file naming
        let current_utc: DateTime<Utc> = Utc::now();
        let mut push_time: String = current_utc.to_string();
        //let mut push_time: String = current_utc.to_rfc3339().replace(":", "-");
        //push_time = push_time.replace("+", "_");

        let sql_cmd = format!(
            "SELECT DISTINCT
             year(stime) AS year, 
             month(stime) AS month, 
             day(stime) as day
             FROM read_parquet({});",
            parquet_list
        );
        
        // SELECT EXTRACT(EPOCH FROM timestamp_column) FROM my_table;
        let mut stmt = self.db_conn.prepare(&sql_cmd).expect("db prepare()");
        let dtg_iter = stmt
            .query_map([], |row| {
                Ok(DistinctDay {
                    year: row.get(0)?,
                    month: row.get(1)?,
                    day: row.get(2)?
                })
            })
            .expect("query_map()");

        for dtg_entry in dtg_iter {
            let dtg = dtg_entry.unwrap();

            if self.filter.is_empty() {
                let sql_record = format!(
                    "CREATE OR REPLACE TABLE flow AS SELECT * FROM read_parquet({});", parquet_list);
                self.db_conn.execute_batch(&sql_record).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;
                
                let sql_record_count = format!("SELECT count() FROM flow;");
                let mut stmt = self.db_conn.prepare(&sql_record_count).map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("DuckDB prepare error: {}", e),
                    )
                })?;
                let record_count = stmt
                    .query_row([], |row| Ok(row.get::<_, u64>(0)?))
                    .map_err(|e| {
                        Error::new(
                            std::io::ErrorKind::Other,
                            format!("DuckDB prepare error: {}", e),
                        )
                    })?;
                if record_count == 0 {
                    println!("{}: done.", self.command);
                    return Ok(());
                }         

                println!("{}: sending {} records to [{}/year={}/month={}/day={}]...",
                    self.command,
                    record_count,
                    self.output_list[0],
                    dtg.year,
                    dtg.month,
                    dtg.day
                );

                let sql_s3_copy = format!(
                    "COPY (SELECT *, year(stime) AS year, month(stime) AS month, day(stime) as day FROM flow
                     WHERE year = {} AND month = {} AND day = {}) 
                     TO '{}/year={}/month={}/day={}/{}{:02}{:02}-{}.parquet' (FORMAT 'parquet', CODEC 'zstd', ROW_GROUP_SIZE 100_000);",  
                    dtg.year, dtg.month, dtg.day,
                    self.output_list[0],
                    dtg.year, dtg.month, dtg.day,
                    dtg.year, dtg.month, dtg.day, push_time);

                self.db_conn.execute_batch(&sql_s3_copy).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;

                self.db_conn.execute_batch("DROP TABLE IF EXISTS flow;").map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;
                
            } else {
                let sql_filter = format!(
                    "CREATE OR REPLACE TABLE flow AS SELECT * FROM read_parquet({}) WHERE {};", parquet_list, self.filter);
                self.db_conn.execute_batch(&sql_filter).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;

                let sql_filter_count = format!("SELECT count() FROM flow;");
                let mut stmt = self.db_conn.prepare(&sql_filter_count).map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("DuckDB prepare error: {}", e),
                    )
                })?;
                let filter_count = stmt
                    .query_row([], |row| Ok(row.get::<_, u64>(0)?))
                    .map_err(|e| {
                        Error::new(
                            std::io::ErrorKind::Other,
                            format!("DuckDB prepare error: {}", e),
                        )
                    })?;
                if filter_count == 0 {
                    println!("{}: done.", self.command);
                    return Ok(());
                }               

                println!(
                    "{}: sending {} records to [{}/year={}/month={}/day={}]...",
                    self.command,
                    filter_count,
                    self.output_list[0],
                    dtg.year,
                    dtg.month,
                    dtg.day
                );
                let sql_s3_copy = format!(
                    "COPY (SELECT *, year(stime) AS year, month(stime) AS month, day(stime) as day FROM flow 
                        WHERE year = {} AND month = {} AND day = {}) 
                        TO '{}/year={}/month={}/day={}/{}{:02}{:02}-{}.parquet' (FORMAT 'parquet', CODEC 'zstd', ROW_GROUP_SIZE 100_000);",
                    dtg.year, dtg.month, dtg.day, 
                    self.output_list[0],
                    dtg.year, dtg.month, dtg.day, 
                    dtg.year, dtg.month, dtg.day, push_time);
            
                self.db_conn.execute_batch(&sql_s3_copy).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;

                self.db_conn.execute_batch("DROP TABLE IF EXISTS flow;").map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;
            }
        }
        println!("{}: done.", self.command);
        Ok(())
    }
    fn local_storage(&mut self, file_list: &Vec<String>) -> Result<(), Error> {
        println!(
            "{}: using to local partitioned storage {}",
            self.command, self.output_list[0]
        );
        // Use iterator and join for file list formatting
        let parquet_list = file_list
            .iter()
            .map(|file| format!("'{}'", file))
            .collect::<Vec<_>>()
            .join(",");
        let parquet_list = format!("[{}]", parquet_list);

        let mut sql_command = String::new();
        if self.filter.is_empty() {
            sql_command = format!(
                "COPY (SELECT *, year(stime) AS year, month(stime) AS month, day(stime) as day, hour(stime) as hour FROM read_parquet({})) 
                    TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000, PARTITION_BY(year, month, day, hour), APPEND, FILENAME_PATTERN 'gnat-{{uuid}}');",
                parquet_list, self.output_list[0]
            );
        } else {
            sql_command = format!(
                "COPY (SELECT *, year(stime) AS year, month(stime) AS month, day(stime) as day, hour(stime) as hour  FROM read_parquet({}) WHERE {}) 
                    TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000, PARTITION_BY(year, month, day, hour), APPEND, FILENAME_PATTERN 'gnat-{{uuid}}');",
                parquet_list, self.filter, self.output_list[0]
            );
        }

        self.db_conn
            .execute_batch(&sql_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        Ok(())
    }
}
impl FileProcessor for StoreProcessor {
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
        match self.storage_type {
            StorageType::MOTHERDUCK => {
                self.upload_to_motherduck(file_list)?;
            }
            StorageType::S3 => {
                self.upload_to_s3(file_list)?;
            }
            StorageType::LOCAL => {
                self.local_storage(file_list)?;
            }
            _ => {
                return Err(Error::other("unsupported storage type"));
            }
        }
        Ok(())
    }
}
