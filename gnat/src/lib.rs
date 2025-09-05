/*!
 *  Galileo Network Analytics (GNA) Toolkit
 *
 *  Copyright 2024 Fidelis Farm & Technologies, LLC
 *  All Rights Reserved.
 *  See license information in LICENSE.
 */

pub mod ipfix {
    pub mod libfixbuf;
}

pub mod utils {
    pub mod duckdb;
}

pub mod model {
    pub mod binning;
    pub mod histogram;
    pub mod table;
}

pub mod pipeline {
    use crate::utils::duckdb::duckdb_open_memory;
    use chrono::DateTime;
    use chrono::Datelike;
    use chrono::Timelike;
    use chrono::Utc;
    use dotenv::dotenv;
    use duckdb::params;
    use std::collections::HashMap;
    use std::env;
    use std::env::VarError;
    use std::fs;
    use std::io::Error;
    use std::path::Path;
    use std::process;
    use std::thread;
    use std::time::Duration;
    use std::time::Instant;

    const MAX_BATCH: usize = 1024;

    pub mod aggregate;
    pub mod cache;
    pub mod collector;
    pub mod export;
    pub mod hbos;
    pub mod import;
    pub mod merge;
    pub mod model;
    pub mod rule;
    pub mod sample;
    pub mod split;
    pub mod store;
    pub mod tag;

    static FIELDS: &'static [&'static str] = &[
        "stream",
        "id",
        "observe",
        "stime",
        "etime",
        "dur",
        "rtt",
        "pcr",
        "proto",
        "saddr",
        "daddr",
        "sport",
        "dport",
        "iflags",
        "uflags",
        "stcpseq",
        "dtcpseq",
        "stcpurg",
        "dtcpurg",
        "svlan",
        "dvlan",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "sentropy",
        "dentropy",
        "siat",
        "diat",
        "sstdev",
        "dstdev",
        "ssmallpktcnt",
        "dsmallpktcnt",
        "slargepktcnt",
        "dlargepktcnt",
        "snonemptypktcnt",
        "dnonemptypktcnt",
        "sfirstnonemptycnt",
        "dfirstnonemptycnt",
        "smaxpktsize",
        "dmaxpktsize",
        "sstdevpayload",
        "dstdevpayload",
        "spd",
        "reason",
        "orient",
        "tag",
        "smac",
        "dmac",
        "scountry",
        "dcountry",
        "sasn",
        "dasn",
        "sasnorg",
        "dasnorg",
        "hbos_score",
        "hbos_severity",
        "hbos_map",
        "ndpi_appid",
        "ndpi_category",
        "ndpi_risk_bits",
        "ndpi_risk_score",
        "ndpi_risk_severity",
        "ndpi_risk_list",
        "trigger",
    ];

    #[derive(Debug, Clone, PartialEq)]
    pub enum StreamType {
        NONE = 0,
        IPFIX = 10,
        LEGACY = 3,
        FLOW = 100,
        TELEMETRY = 300,
        EXPORTED = 800,
        ADHOC = 900,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum Interval {
        ONCE,
        SECOND,
        MINUTE,
        HOUR,
        DAY,
        WEEK,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum FileType {
        UNKNOWN,
        IPFIX_YAF,
        JSON,
        CSV,
        PARQUET_FLOW3,
        PARQUET_FLOW4,
        PARQUET_FLOW5,
        UNSUPPORTED,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum StorageType {
        UNSUPPORTED,
        LOCAL,
        S3,
        MOTHERDUCK,
    }

    pub fn parse_interval(interval_string: &str) -> Interval {
        match interval_string {
            "once" => Interval::ONCE,
            "second" => Interval::SECOND,
            "minute" => Interval::MINUTE,
            "hour" => Interval::HOUR,
            "day" => Interval::DAY,
            "week" => Interval::WEEK,
            _ => Interval::SECOND,
        }
    }
    pub fn parse_options(options_string: &str) -> HashMap<&str, &str> {
        if options_string.is_empty() {
            let options: HashMap<&str, &str> = HashMap::new();
            return options;
        }

        let options: HashMap<&str, &str> = options_string
            .split(";")
            .map(|s| s.split_at(s.find("=").expect("error: missing option(s)")))
            .map(|(key, val)| (key, &val[1..]))
            .collect();

        options
    }
    fn sleep_interval(interval: &Interval) -> bool {
        let last = Utc::now();
        let sleep_interval = Duration::from_secs(1);

        loop {
            thread::sleep(sleep_interval);

            let now = Utc::now();
            match interval {
                Interval::SECOND => {
                    return true;
                }
                Interval::MINUTE => {
                    if now.minute() != last.minute() {
                        return true;
                    }
                }
                Interval::HOUR => {
                    if now.hour() != last.hour() {
                        return true;
                    }
                }
                Interval::DAY => {
                    if now.day() != last.day() {
                        return true;
                    }
                }
                Interval::WEEK => {
                    let delta = now - last;
                    if delta.num_days() >= 7 {
                        return true;
                    }
                }
                _ => {
                    return false;
                }
            }
        }
    }

    fn check_and_update_schema(file_list: &Vec<String>) -> Result<(), Error> {
        if file_list[0].ends_with(".yaf") {
            return Ok(());
        }

        let db_conn = duckdb_open_memory(1)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        let sql_exists_command = format!(
            "SELECT EXISTS(SELECT 1 FROM parquet_schema('{}') WHERE name = 'stream')",
            file_list[0]
        );
        let mut stmt = db_conn
            .prepare(&sql_exists_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        let is_current_schema = stmt
            .query_row([], |row| Ok(row.get::<_, bool>(0).expect("missing stream")))
            .expect("missing stream");

        if !is_current_schema {
            for file in file_list {
                let tmp_file = format!("{}.updated", file);
                let sql_get_stream = format!(
                    "CREATE OR REPLACE TABLE flow AS SELECT * FROM '{}'; 
                     ALTER TABLE flow RENAME version TO stream;
                     UPDATE flow SET stream = 100;",
                    file
                );

                db_conn.execute_batch(&sql_get_stream).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;

                match db_conn.execute(
                    "COPY flow TO '?' (FORMAT parquet, CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
                    params![tmp_file],
                ) {
                    Ok(count) => {
                        if count > 0 {
                            fs::remove_file(file)?;
                            fs::rename(&tmp_file, &file)?;
                        } else {
                            if !Path::new(&tmp_file).exists() {
                                fs::remove_file(&tmp_file)?;
                            }
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
        }
        Ok(())
    }

    fn check_parquet_stream(parquet_files: &str) -> Result<bool, Error> {
        let db_conn = duckdb_open_memory(1)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        let sql_distinct_stream = format!(
            "SELECT count(DISTINCT stream) FROM read_parquet({});",
            parquet_files
        );
        let mut stmt = db_conn.prepare(&sql_distinct_stream).expect("sql prepare");

        let distinct_count = stmt
            .query_row([], |row| Ok(row.get::<_, u32>(0).unwrap_or(0)))
            .unwrap_or(0);
        let _ = db_conn.close().expect("failed to close db connection");

        return Ok(distinct_count == 1);
    }

    pub fn load_environment() -> Result<(), VarError> {
        dotenv().ok();
        Ok(())
    }
    pub fn use_motherduck(output: &str) -> Result<bool, VarError> {
        if output.starts_with("md:") {
            let motherduck_token = env::var("motherduck_token");
            if motherduck_token.is_ok() {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    pub fn use_s3(output: &str) -> Result<bool, VarError> {
        if output.starts_with("s3:") {
            let motherduck_token = env::var("motherduck_token");
            if motherduck_token.is_ok() {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    pub trait FileProcessor {
        fn process(&mut self, file_list: &Vec<String>) -> Result<(), Error>;
        fn socket(&mut self) -> Result<(), Error>;
        fn get_command(&self) -> &String;
        fn get_input(&self, input_list: &mut Vec<String>) -> Result<(), Error>;
        fn get_output(&self, output_list: &mut Vec<String>) -> Result<(), Error>;
        fn get_stream_id(&self) -> u32;
        fn get_pass(&self) -> &String;
        fn get_file_extension(&self) -> &String;
        fn get_interval(&self) -> &Interval;
        fn delete_files(&self) -> bool;

        fn listen(&mut self) -> Result<(), Error> {
            self.socket()
        }
        fn export_parquet(
            &mut self,
            parquet_list: String,
            output_list: &Vec<String>,
        ) -> Result<(), Error> {
            Ok(())
        }

        fn forward(&mut self, parquet_list: &str, output_list: &Vec<String>) -> Result<i64, Error> {
            let command = self.get_command().clone();
            let current_utc: DateTime<Utc> = Utc::now();
            let rfc3339_name: String = current_utc.to_rfc3339();
            // Sanitize rfc3339_name for filesystem safety
            let safe_rfc3339 = rfc3339_name.replace(":", "-");
            let mut record_count: i64 = 0;
            let db_out = duckdb_open_memory(1).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;
            for output in output_list {
                let sql = format!(
                    "CREATE OR REPLACE TABLE flow AS SELECT * FROM read_parquet({});",
                    parquet_list
                );
                db_out.execute_batch(&sql).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;
                let mut stmt = db_out.prepare("SELECT COUNT(*) FROM flow;").map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;
                record_count = stmt.query_row([], |row| row.get(0)).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;

                if record_count > 0 {
                    let tmp_filename =
                        format!("{}/.gnat-{}-{}.parquet", output, command, safe_rfc3339);
                    let final_filename =
                        format!("{}/gnat-{}-{}.parquet", output, command, safe_rfc3339);
                    let sql = format!("COPY flow TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);", tmp_filename);
                    db_out.execute_batch(&sql).map_err(|e| {
                        Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                    })?;

                    fs::rename(&tmp_filename, &final_filename)?;
                }
            }
            let _ = db_out.close();
            Ok(record_count)
        }

        fn process_directory(
            &mut self,
            input: &str,
            pass: &str,
            file_extension: &str,
        ) -> Result<usize, Error> {
            let command = self.get_command().clone();
            let mut file_list: Vec<String> = Vec::new();
            let mut pass_list: Vec<String> = Vec::new();

            let mut total_files_processed = 0;
            loop {
                file_list.clear();
                pass_list.clear();
                for entry in fs::read_dir(input)? {
                    let file: fs::DirEntry = entry.unwrap();
                    let file_name = String::from(file.file_name().to_string_lossy());
                    if !file_name.starts_with(".") && file_name.ends_with(&file_extension) {
                        // make sure yaf file is not locked
                        let file_path = format!("{}/{}", input, file_name);

                        if file_path.ends_with(".yaf") {
                            if !Path::new(&format!("{}.lock", file_path)).exists() {
                                file_list.push(file_path);
                                if !pass.is_empty() {
                                    let pass_path = format!("{}/{}", pass, file_name);
                                    pass_list.push(pass_path);
                                }
                            }
                        } else {
                            file_list.push(file_path);
                            if !pass.is_empty() {
                                let pass_path = format!("{}/{}", pass, file_name);
                                pass_list.push(pass_path);
                            }
                        }
                    }
                    // batch up to MAX_BATCH -- limit the number of files process at once
                    if file_list.len() >= MAX_BATCH {
                        break;
                    }
                }

                if !file_list.is_empty() {
                    //check_and_update_schema(&file_list).expect("failed to update legacy schema");

                    //
                    // process files
                    //
                    match self.process(&file_list) {
                        Ok(_) => {}
                        Err(error) => {
                            eprintln!("{}: processing failed: {}", command, error);
                            std::process::exit(exitcode::IOERR);
                        }
                    }

                    //
                    // move files to pass through directory or delete
                    //
                    for (index, file) in file_list.iter_mut().enumerate() {
                        if pass_list.is_empty() {
                            if self.delete_files() {
                                fs::remove_file(file)?;
                            }
                        } else {
                            fs::rename(&file, &pass_list[index])?;
                        }
                    }
                }
                total_files_processed += file_list.len();
                if file_list.len() < MAX_BATCH {
                    break;
                }
            }
            Ok(total_files_processed)
        }
        fn run(&mut self) -> Result<(), Error> {
            let command = self.get_command().clone();

            let mut input_list = Vec::new();
            let mut output_list = Vec::new();
            let _ = self.get_input(&mut input_list)?;
            let _ = self.get_output(&mut output_list)?;
            let pass = self.get_pass().clone();
            let interval = self.get_interval().clone();
            let file_extension = self.get_file_extension().clone();

            // Change the current working directory
            // This is necessary for the DuckDB to work correctly with the temp directory
            // and to ensure that the output files are written to the correct location
            // This is a workaround for the DuckDB issue with temp directory
            //
            let _ = env::set_current_dir(&input_list[0])?;
            println!(
                "{}: pwd spec: {:?}",
                command,
                env::current_dir().unwrap().display()
            );

            println!("{}: input spec: {:?}", command, input_list);
            println!("{}: output spec: {:?}", command, output_list);

            if !pass.is_empty() {
                println!("{}: pass spec: [{}]", command, pass);
            }
            let interval_string = match interval {
                Interval::ONCE => "one",
                Interval::MINUTE => "minute",
                Interval::HOUR => "hour",
                Interval::DAY => "day",
                _ => "second",
            };

            println!("{}: interval: [{}]", command, interval_string);
            //
            // verify the combination of arguments are valid
            //
            for input in input_list.iter() {
                if !Path::new(&input).exists() {
                    eprintln!(
                        "Commandline error: input directory {} does not exist",
                        input
                    );
                    std::process::exit(exitcode::CONFIG)
                }
            }
            for output in output_list.iter() {
                if output.starts_with("md:") || output.starts_with("s3:") {
                } else if !Path::new(&output).exists() {
                    eprintln!(
                        "commandline error: output directory {} does not exist",
                        output
                    );
                    std::process::exit(exitcode::CONFIG)
                }
            }
            if !pass.is_empty() && !Path::new(&pass).is_dir() {
                eprintln!("commandline error: invalid --pass {}", pass);
                std::process::exit(exitcode::CONFIG)
            }

            println!("{}: starting up.", command);

            // wait for the initial interval to start
            if interval != Interval::ONCE {
                if !sleep_interval(&interval) {
                    println!("{}: shutting down.", command);
                    return Ok(());
                }
            }

            loop {
                let start = Instant::now();
                let mut total_files_processed = 0;
                // process all input directories
                for input in &input_list {
                    total_files_processed +=
                        self.process_directory(&input, &pass, &file_extension)?;
                }

                if total_files_processed > 0 {
                    println!(
                        "{}: processed {} file(s) in {:?}",
                        command,
                        total_files_processed,
                        start.elapsed()
                    );
                }

                if !sleep_interval(&interval) {
                    println!("{}: shutting down.", command);
                    return Ok(());
                }
            }
        }
    }
}
