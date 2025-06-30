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
    use std::collections::HashMap;
    use std::env;
    use std::env::VarError;
    use std::fs;
    use std::io::Error;
    use std::path::Path;
    use std::thread;
    use std::time::Duration;
    use std::time::Instant;
    const MAX_BATCH: usize = 64;

    pub mod aggregate;
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
        IPFIX = 10,
        LEGACY = 3,
        FLOW = 100,
        TELEMETRY = 300,
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

        let db_conn = duckdb_open_memory(1);
        let sql_exists_command = format!(
            "SELECT EXISTS(SELECT 1 FROM parquet_schema('{}') WHERE name = 'stream')",
            file_list[0]
        );
        let mut stmt = db_conn.prepare(&sql_exists_command).expect("sql prepare");
        let is_current_schema = stmt
            .query_row([], |row| Ok(row.get::<_, bool>(0).expect("missing stream")))
            .expect("missing stream");

        if !is_current_schema {
            for file in file_list {
                let tmp_file = format!("{}.updated", file);
                let sql_get_stream = format!(
                    "CREATE OR REPLACE TABLE flow AS SELECT * FROM '{}'; 
                     ALTER TABLE flow RENAME version TO stream;
                     UPDATE flow SET stream = 100;
                     COPY flow TO '{}' (FORMAT parquet);",
                    file, tmp_file
                );

                db_conn.execute_batch(&sql_get_stream).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;

                fs::remove_file(file).expect("failed to remove old file");
                fs::rename(tmp_file.as_str(), file.as_str()).expect("failed to rename new file");
            }
        }
        Ok(())
    }

    fn get_stream_class(file: &String) -> Result<u32, Error> {
        if file.ends_with(".yaf") {
            return Ok(StreamType::IPFIX as u32);
        } else if file.ends_with(".parquet") {
            let db_conn = duckdb_open_memory(1);
            let sql_get_stream = format!("SELECT stream FROM read_parquet('{}') LIMIT 1;", file);
            let mut stmt = db_conn.prepare(&sql_get_stream).expect("sql prepare");
            let stream_class = stmt
                .query_row([], |row| {
                    Ok(row.get::<_, u32>(0).expect("missing stream_class"))
                })
                .expect("missing stream_class");
            return Ok(stream_class as u32);
        }
        return Err(Error::other("unsupported file type"));
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
        fn forward(
            &mut self,
            parquet_list: String,
            output_list: &Vec<String>,
        ) -> Result<(), Error> {
            let current_utc: DateTime<Utc> = Utc::now();
            let rfc3339_name: String = current_utc.to_rfc3339();
            // Sanitize rfc3339_name for filesystem safety
            let safe_rfc3339 = rfc3339_name.replace(":", "-");

            let db_out = duckdb_open_memory(2);
            for output in output_list {
                let tmp_filename = format!(
                    "{}/.gnat-{}-{}.parquet",
                    output,
                    self.get_command(),
                    safe_rfc3339
                );
                let final_filename = format!(
                    "{}/gnat-{}-{}.parquet",
                    output,
                    self.get_command(),
                    safe_rfc3339
                );

                let sql_command = format!(
                    "COPY (SELECT * FROM read_parquet({})) TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
                    parquet_list, tmp_filename
                );
                db_out.execute_batch(&sql_command).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;

                fs::rename(&tmp_filename, &final_filename).map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("File rename error: {}", e),
                    )
                })?;
            }
            let _ = db_out.close();
            Ok(())
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
            //println!("{}: processing directory {}", command, input);

            for entry in fs::read_dir(input).expect("read_dir()") {
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
                // make sure stream types are compatible
                //

                check_and_update_schema(&file_list).expect("failed to update legacy schema");

                let stream_class =
                    get_stream_class(&file_list[0]).expect("get stream class version");
                if (stream_class == StreamType::IPFIX as u32 && command == "import")
                    || stream_class == StreamType::FLOW as u32
                {
                    println!("{}: processing {} file(s) ...", command, file_list.len());
                } else {
                    eprintln!("{}: unsupported stream class: {}", command, stream_class);
                    eprintln!("{}: check gnat pipeline configuration", command);
                    std::process::exit(exitcode::CONFIG);
                }
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
                // move files to pass or delete
                //
                for (index, file) in file_list.iter_mut().enumerate() {
                    if pass_list.is_empty() {
                        if self.delete_files() {
                            fs::remove_file(file).expect("failed to remove file");
                        }
                    } else {
                        fs::rename(&file, &pass_list[index]).expect("failed to rename file");
                    }
                }
            }
            Ok(file_list.len())
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

            loop {
                let start = Instant::now();
                let mut total_files_processed = 0;
                // process all input directories
                for input in &input_list {
                    total_files_processed += self
                        .process_directory(&input, &pass, &file_extension)
                        .expect("failed to process directory");
                }

                if total_files_processed == 0 {
                    if !sleep_interval(&interval) {
                        println!("{}: shutting down.", command);
                        return Ok(());
                    }
                } else {
                    println!("{}: elapsed time {:?}", command, start.elapsed());
                }
            }
        }
    }
}
