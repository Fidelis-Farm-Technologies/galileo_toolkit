/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::model::histogram::MD_FLOW_TABLE;
use crate::pipeline::use_motherduck;
use crate::pipeline::StorageType;
use crate::utils::duckdb::{duckdb_open, duckdb_open_memory, duckdb_open_readonly};
use dotenv::dotenv;
use duckdb::Connection;
use std::env;

use crate::model::table::MemFlowRecord;
use chrono::{DateTime, TimeZone, Utc};

use duckdb::{params, Appender, DropBehavior};
use std::fs;
use std::process;
use std::time::Instant;
use std::time::SystemTime;

use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::FileType;
use crate::pipeline::Interval;
use std::io::Error;

#[derive(Debug)]
struct DistinctDtg {
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
}

pub struct StoreProcessor {
    pub command: String,
    pub input: String,
    pub output: String,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
    pub storage_type: StorageType,
    pub db_conn: Connection,
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
        let interval = parse_interval(interval_string);
        let mut options = parse_options(options_string);
        let storage_type = Self::get_storage_type(output)?;

        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}={}]", command, key, value);
            }
        }

        let mut db_conn = duckdb_open_memory(2);

        if storage_type == StorageType::MOTHERDUCK {
            db_conn = duckdb_open(output, 2);
            db_conn.execute_batch(MD_FLOW_TABLE).expect("execute_batch");
            println!("{}: connection established with {}", command, output);
        } else if storage_type == StorageType::S3 {
            let s3_region = env::var("s3_region").expect("missing S3 region");
            let s3_endpoint = env::var("s3_endpoint").expect("missing S3 endpoint");
            let s3_access_key_id = env::var("s3_access_key_id").expect("missing S3 access key ID");
            let s3_secret_access_key =
                env::var("s3_secret_access_key").expect("missing S3 secret access key");
            let s3_url_style = env::var("s3_url_style").unwrap_or("path".to_string());

            //
            // load secret credentials
            //
            println!("S3_uploader: initializing...");
            let sql_secret = format!(
                "CREATE SECRET secret (
                 TYPE S3, KEY_ID '{}', 
                 SECRET '{}', 
                 REGION '{}', 
                 ENDPOINT '{}', 
                 URL_STYLE '{}');",
                s3_access_key_id, s3_secret_access_key, s3_region, s3_endpoint, s3_url_style
            );
            db_conn
                .execute_batch(&sql_secret)
                .expect("S3 create secret");
        } else {
            // For local storage, we can use an in-memory connection
            println!("{}: using local storage", command);
        }
        Ok(Self {
            command: command.to_string(),
            input: input.to_string(),
            output: output.to_string(),
            pass: pass.to_string(),
            interval,
            extension: extension_string.to_string(),
            storage_type: storage_type,
            db_conn: db_conn,
        })
    }

    pub fn get_storage_type(output: &str) -> Result<StorageType, Error> {
        if output.starts_with("md:") {
            dotenv().ok();
            let motherduck_token = env::var("motherduck_token");
            if motherduck_token.is_ok() {
                return Ok(StorageType::MOTHERDUCK);
            }
        } else if output.starts_with("s3://") {
            dotenv().ok();
            let s3_bucket = env::var("s3_bucket");
            if !s3_bucket.is_ok() {
                return Err(Error::other("missing S3 bucket name"));
            }

            let s3_partition = env::var("s3_partition");
            if !s3_partition.is_ok() {
                return Err(Error::other("missing S3 partition"));
            }
            let s3_region = env::var("s3_region");
            if !s3_region.is_ok() {
                return Err(Error::other("missing S3 region"));
            }
            let s3_endpoint = env::var("s3_endpoint");
            if !s3_endpoint.is_ok() {
                return Err(Error::other("missing S3 endpoint"));
            }
            let s3_access_key_id = env::var("s3_access_key_id");
            if !s3_access_key_id.is_ok() {
                return Err(Error::other("missing S3 access key ID"));
            }
            let s3_secret_access_key = env::var("s3_secret_access_key");
            if !s3_secret_access_key.is_ok() {
                return Err(Error::other("missing S3 secret access key"));
            }
            return Ok(StorageType::S3);
        } else if output.starts_with("file:") || output.starts_with("/") {
            return Ok(StorageType::LOCAL);
        }
        return Err(Error::other("unsupported storage type"));
    }
    fn upload_to_motherduck(&mut self, file_list: &Vec<String>) -> Result<(), Error> {
        println!("{}: uploading to motherduck...", self.command);
        let start = Instant::now();
        for parquet_file in file_list.clone().into_iter() {
            let sql_export = format!(
                "INSERT INTO flow SELECT * FROM read_parquet('{}')",
                parquet_file
            );
            self.db_conn
                .execute_batch(&sql_export)
                .expect("execute_batch()");
            println!("{}:\t{}", self.command, parquet_file);
        }
        let duration = start.elapsed();
        println!("{}: elapsed time: {:?}", self.command, duration);

        Ok(())
    }
    fn upload_to_s3(&mut self, file_list: &Vec<String>) -> Result<(), Error> {
        println!("{}: uploading to S3...", self.command);

        let mut parquet_list = String::from("[");
        for (_, file) in file_list.clone().into_iter().enumerate() {
            parquet_list.push_str("'");
            parquet_list.push_str(&file);
            parquet_list.push_str("',");
        }
        parquet_list.push_str("]");

        let sql_cmd = format!(
            "SELECT DISTINCT
             year(stime) AS year, 
             month(stime) AS month, 
             day(stime) as day, 
             hour(stime) as hour 
             FROM read_parquet({});",
            parquet_list
        );

        let mut stmt = self.db_conn.prepare(&sql_cmd).expect("db prepare()");
        let dtg_iter = stmt
            .query_map([], |row| {
                Ok(DistinctDtg {
                    year: row.get(0)?,
                    month: row.get(1)?,
                    day: row.get(2)?,
                    hour: row.get(3)?,
                })
            })
            .expect("query_map()");

        let start = Instant::now();

        for dtg_entry in dtg_iter {
            let dtg = dtg_entry.unwrap();
            let push_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("now()");
            println!(
                "{}: uploading [{}/year={}/month={}/day={}/hour={}/{}{:02}{:02}{:02}]...",
                self.command,
                self.output,
                dtg.year,
                dtg.month,
                dtg.day,
                dtg.hour,
                dtg.year,
                dtg.month,
                dtg.day,
                dtg.hour
            );

            let sql_s3_copy = format!(
            "COPY (SELECT *, year(stime) AS year, month(stime) AS month, day(stime) as day, hour(stime) as hour FROM read_parquet({})
             WHERE year = {} AND month = {} AND day = {} AND hour = {}) 
             TO '{}/year={}/month={}/day={}/hour={}/{}{:02}{:02}{:02}-{}.parquet' (FORMAT 'parquet', CODEC 'zstd', ROW_GROUP_SIZE 100_000);", 
            //TO 's3://{}/{}/year={}/month={}/day={}/hour={}/{}{:02}{:02}{:02}-{}.parquet' (FORMAT 'parquet', CODEC 'zstd', ROW_GROUP_SIZE 100_000);", 
            parquet_list,
            dtg.year, dtg.month, dtg.day, dtg.hour,
            self.output,
            dtg.year, dtg.month, dtg.day, dtg.hour,
            dtg.year, dtg.month, dtg.day, dtg.hour, push_time.as_secs());
            //println!("S3_uploader: execute_batch {}", sql_s3_copy);
            self.db_conn
                .execute_batch(&sql_s3_copy)
                .expect("S3 execute upload");
        }

        let duration = start.elapsed();
        println!("{}: elapsed time: {:?}", self.command, duration);

        Ok(())
    }
    fn local_storage(&mut self, file_list: &Vec<String>) -> Result<(), Error> {
        println!(
            "{}: updating to local partitioned storage {}",
            self.command, self.output
        );
        // Use iterator and join for file list formatting
        let parquet_list = file_list
            .iter()
            .map(|file| format!("'{}'", file))
            .collect::<Vec<_>>()
            .join(",");
        let parquet_list = format!("[{}]", parquet_list);

        let sql_command = format!(
                "COPY (SELECT * year(stime) AS year, month(stime) AS month, day(stime) as day, hour(stime) as hour  FROM read_parquet({})) 
                 TO '{}' (FORMAT 'parquet', PARTITION_BY(year, month, day, hour), CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
                parquet_list, self.output
            );
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

    fn process(&mut self, file_list: &Vec<String>, schema_version: FileType) -> Result<(), Error> {
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
