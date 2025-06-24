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
    use chrono::Datelike;
    use chrono::Timelike;
    use chrono::Utc;
    use dotenv::dotenv;
    use duckdb::Connection;
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
    pub mod store;
    pub mod tag;

    static FIELDS: &'static [&'static str] = &[
        "version",
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
    pub enum Interval {
        ONCE,
        SECOND,
        MINUTE,
        HOUR,
        DAY,
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
                _ => {
                    return false;
                }
            }
        }
    }
    fn get_file_type(file: &String) -> Result<FileType, Error> {
        if file.ends_with(".yaf") {
            return Ok(FileType::IPFIX_YAF);
        } else if file.ends_with(".parquet") {
            let db_conn = duckdb_open_memory(1);
            let sql_get_version = format!(
                "SELECT DISTINCT version FROM read_parquet('{}') LIMIT 1;",
                file
            );
            let mut stmt = db_conn.prepare(&sql_get_version).expect("sql prepare");
            let version = stmt
                .query_row([], |row| Ok(row.get::<_, u32>(0).expect("missing version")))
                .expect("query row");
            match version {
                0 => Ok(FileType::UNSUPPORTED),
                1 => Ok(FileType::UNSUPPORTED),
                2 => Ok(FileType::UNSUPPORTED),
                3 => Ok(FileType::PARQUET_FLOW3),
                4 => Ok(FileType::PARQUET_FLOW4),
                _ => Ok(FileType::UNKNOWN),
            }
        } else {
            return Err(Error::other("unsupported file type"));
        }
    }
    pub fn use_motherduck(output: &str) -> Result<bool, VarError> {
        if output.starts_with("md:") {
            dotenv().ok();
            let motherduck_token = env::var("motherduck_token");
            if motherduck_token.is_ok() {
                return Ok(true);
            }
        }
        return Ok(false);
    }

    pub trait FileProcessor {
        fn process(&mut self, file_list: &Vec<String>, schema_type: FileType) -> Result<(), Error>;
        fn socket(&mut self) -> Result<(), Error>;
        fn get_command(&self) -> &String;
        fn get_input(&self) -> &String;
        fn get_output(&self) -> &String;
        fn get_pass(&self) -> &String;
        fn get_file_extension(&self) -> &String;
        fn get_interval(&self) -> &Interval;
        fn delete_files(&self) -> bool;

        fn listen(&mut self) -> Result<(), Error> {
            self.socket()
        }

        fn run(&mut self) -> Result<(), Error> {
            let command = self.get_command().clone();
            let input = self.get_input();
            let output = self.get_output();
            let pass = self.get_pass().clone();
            let interval = self.get_interval().clone();
            let file_extension = self.get_file_extension().clone();

            println!("{}: input spec: [{}]", command, input);
            println!("{}: output spec: [{}]", command, output);
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
            if !Path::new(&input).is_dir() {
                eprintln!("Commandline error: invalid --input {}", input);
                std::process::exit(exitcode::CONFIG)
            }

            if !pass.is_empty() && !Path::new(&pass).is_dir() {
                eprintln!("Commandline error: invalid --pass {}", pass);
                std::process::exit(exitcode::CONFIG)
            }

            let input_dir = Path::new(input.as_str());
            env::set_current_dir(input_dir)?;
            println!("{}: current working directory: {}.", command, input);
            println!("{}: starting up.", command);

            loop {
                let mut more_to_process = false;
                let mut file_list: Vec<String> = Vec::new();
                for entry in fs::read_dir(".").expect("read_dir()") {
                    let file: fs::DirEntry = entry.unwrap();
                    let file_name = String::from(file.file_name().to_string_lossy());
                    if !file_name.starts_with(".") && file_name.ends_with(&file_extension) {
                        // make sure yaf file is not locked
                        if file_name.ends_with(".yaf") {
                            if !Path::new(&format!("{}.lock", file_name)).exists() {
                                file_list.push(file_name);
                            }
                        } else {
                            file_list.push(file_name);
                        }
                    }
                    // batch up to MAX_BATCH -- limit the number of files process at once
                    if file_list.len() >= MAX_BATCH {
                        more_to_process = true;
                        break;
                    }
                }

                if !file_list.is_empty() {
                    // first file represents the schema version for the batch
                    let schema_type = get_file_type(&file_list[0]).expect("get schema version");

                    if schema_type == FileType::IPFIX_YAF {
                        println!(
                            "{}: processing {} ipfix file(s) ...",
                            command,
                            file_list.len()
                        );
                    } else if schema_type == FileType::PARQUET_FLOW3 {
                        println!(
                            "{}: processing {} parquet file(s) (schema version {:?})...",
                            command,
                            file_list.len(),
                            schema_type
                        );
                    } else {
                        eprintln!("{}: unsupported schema version {:?}.", command, schema_type);
                        std::process::exit(exitcode::CONFIG)
                    }
                    //
                    // process files
                    //
                    let start = Instant::now();
                    match self.process(&file_list, schema_type) {
                        Ok(_) => {}
                        Err(error) => {
                            eprintln!("{}: processing failed: {}", command, error);
                            std::process::exit(exitcode::IOERR);
                        }
                    }
                    println!("{}: elapsed time: {:?}", command, start.elapsed());
                    
                    //
                    // move files to pass or delete
                    //
                    for file in file_list.iter_mut() {
                        if pass.is_empty() {
                            if self.delete_files() {
                                fs::remove_file(file).expect("failed to remove file");
                            }
                        } else {
                            let mut pass_file = format!("{}/{}", &pass, file);

                            fs::rename(file.clone(), pass_file.clone())
                                .expect("failed to rename file");
                        }
                    }

                    if more_to_process {
                        continue;
                    }
                }

                if !sleep_interval(&interval) {
                    println!("{}: shutting down.", command);
                    return Ok(());
                }
            }
        }
    }
}
