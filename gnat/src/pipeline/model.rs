/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::model::histogram::histogram_model::HistogramModels;
use crate::model::histogram::ipaddr_category::IpAddrCategoryHistogram;
use crate::model::histogram::number::NumberHistogram;
use crate::model::histogram::numeric_category::NumericCategoryHistogram;
use crate::model::histogram::string_category::StringCategoryHistogram;
use crate::model::histogram::time_category::TimeCategoryHistogram;
use crate::model::histogram::MINIMUM_DAYS;

use crate::pipeline::check_parquet_stream;
use crate::pipeline::load_environment;
use crate::pipeline::use_motherduck;
use crate::pipeline::StreamType;

use crate::model::histogram::PARQUET_DISTINCT_OBSERVATIONS;
use crate::model::table::DistinctObservation;
use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::Interval;
use chrono::Datelike;
use chrono::{DateTime, Utc};

use crate::utils::duckdb::{duckdb_open, duckdb_open_memory};

use std::collections::HashMap;
use std::fs;
use std::io::Error;
use std::path::Path;

pub struct ModelProcessor {
    pub command: String,
    pub input_list: Vec<String>,
    pub model_list: Vec<String>,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
    pub feature_list: Vec<String>,
    pub protocol_list: Vec<String>,
    pub md_database: String,
}

impl ModelProcessor {
    pub fn new<'a>(
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
        options
            .entry("features")
            .or_insert("daddr,dport,dentropy,sentropy,diat,siat,spd,pcr,orient,stime");
        options.entry("proto").or_insert("udp,tcp");
        options.entry("md").or_insert("");

        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}=>{}]", command, key, value);
            }
        }

        let mut md_database = options.get("md").expect("expected model").to_string();
        if !md_database.is_empty() {
            let md_parameter = format!("md:{}", md_database);
            if use_motherduck(&md_parameter).expect("motherduck env") {
                println!("{}: [motherduck={}]", command, md_database);
            } else {
                md_database.clear();
            }
        }
        let features = options.get("features").expect("expected feature list");
        let feature_list: Vec<String> = features.split(",").map(str::to_string).collect();

        let mut protocols = options
            .get("proto")
            .expect("expected proto list")
            .to_string();
        let protocol_list: Vec<String> = protocols.split(",").map(str::to_string).collect();

        let mut input_list = Vec::<String>::new();
        input_list.push(input.to_string());
        let mut model_list = Vec::<String>::new();
        model_list.push(output.to_string());
        Ok(Self {
            command: command.to_string(),
            input_list: input_list,
            model_list: model_list,
            pass: pass.to_string(),
            interval: interval,
            extension: extension_string.to_string(),
            feature_list: feature_list,
            protocol_list: protocol_list,
            md_database: md_database.to_string(),
        })
    }

    fn upload_model(&self, model_file: &str) -> Result<(), Error> {
        // if the md_database is empty, we do not upload the model
        if !self.md_database.is_empty() {
            println!(
                "{}: uploading model {} to motherduck",
                self.command, self.md_database
            );

            let md_conn = duckdb_open("md:", 1).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;
            // upload the model to motherduck
            let sql_command = format!(
                "COPY FROM DATABASE {} (OVERWRITE) TO md:{};",
                model_file, self.md_database
            );

            md_conn.execute_batch(&sql_command).map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("DuckDB error during model upload: {}", e),
                )
            })?;

            let _ = md_conn.close();
            println!("{}: done.", self.command);
        }

        Ok(())
    }
}
impl FileProcessor for ModelProcessor {
    fn get_command(&self) -> &String {
        &self.command
    }
    fn get_input(&self, input_list: &mut Vec<String>) -> Result<(), Error> {
        *input_list = self.input_list.clone();
        Ok(())
    }
    fn get_output(&self, output_list: &mut Vec<String>) -> Result<(), Error> {
        //*output_list = self.model_list.clone();
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
        false
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
        // check if the model file exists, if so, the age
        // is checked to determine if a new model should be built
        if Path::new(&self.model_list[0]).exists() {
            if self.interval != Interval::ONCE {
                // check if the current model is a day old, if so build a new one
                let meta = fs::metadata(&self.model_list[0]).map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to get metadata: {}", e),
                    )
                })?;
                let ctime_local = meta.created().map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to get created time: {}", e),
                    )
                })?;
                let ctime_utc: DateTime<Utc> = ctime_local.into();
                if Utc::now().day() == ctime_utc.day() {
                    // no change
                    return Ok(());
                }
                println!(
                    "{}: overwriting existing model file: {}",
                    self.command, self.model_list[0]
                );
            }
        }

        // load the parquet files into a temporary duckdb database
        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        let tmp_input = format!(
            "{}.{}.tmp",
            self.model_list[0],
            rfc3339_name.replace(":", "-")
        );
        let mut db_input = duckdb_open(&tmp_input, 1)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        // check the number of days in the dataset
        // if there are not enough days, skip the model build
        println!("{}: checking dataset duration...", self.command);
        let sql_days_command = format!(
            "SELECT date_diff('day',first,last) 
             FROM (SELECT MIN(stime) AS first, MAX(stime) AS last FROM read_parquet({}));",
            parquet_list
        );
        let mut stmt = db_input.prepare(&sql_days_command).map_err(|e| {
            Error::new(
                std::io::ErrorKind::Other,
                format!("DuckDB prepare error: {}", e),
            )
        })?;
        let days = stmt
            .query_row([], |row| Ok(row.get::<_, u32>(0).expect("missing version")))
            .expect("missing days");
        if days < MINIMUM_DAYS {
            println!(
                "{}: not enough data to baseline, skipping model build.",
                self.command
            );
            return Ok(());
        }

        println!(
            "{}: modeling {} days of sampled data...",
            self.command, days
        );
        // load observation list
        println!("{}: determining observation points...", self.command);
        let sql_distinct = format!(
            "SELECT DISTINCT observe, dvlan, proto FROM read_parquet({}) GROUP BY ALL ORDER BY ALL;",parquet_list
        );
        let mut stmt = db_input
            .prepare(&sql_distinct)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        let record_iter = stmt
            .query_map([], |row| {
                Ok(DistinctObservation {
                    observe: row.get(0).expect("missing value"),
                    vlan: row.get(1).expect("missing dvlan"),
                    proto: row.get(2).expect("missing proto"),
                })
            })
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        let mut distinct_observation_models: Vec<DistinctObservation> = Vec::new();
        for record in record_iter {
            distinct_observation_models.push(record.map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {:?}", e))
            })?);
        }

        let _ = db_input
            .close()
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {:?}", e)))?;

        if Path::new(&tmp_input).exists() {
            fs::remove_file(&tmp_input).map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to remove file: {}", e),
                )
            })?;
        }

        // build histograms
        let mut distinct_models = HashMap::new();
        for record in &distinct_observation_models {
            // protocol_list filtering
            if !self.protocol_list.is_empty() && !self.protocol_list.contains(&record.proto) {
                // println!(
                //     "{}: skipping protocol {} not in {:?}",
                //     self.command, record.proto, self.protocol_list
                // );
                continue;
            }
            let distinct_key = format!("{}/{}/{}", record.observe, record.vlan, record.proto);
            println!("{}: building histogram [{}]", self.command, distinct_key);
            let numerical_map: HashMap<String, NumberHistogram> = HashMap::new();
            let numerical_cat_map: HashMap<String, NumericCategoryHistogram> = HashMap::new();
            let string_cat_map: HashMap<String, StringCategoryHistogram> = HashMap::new();
            let ipadd_cat_map: HashMap<String, IpAddrCategoryHistogram> = HashMap::new();
            let time_category_map: HashMap<String, TimeCategoryHistogram> = HashMap::new();
            let mut model = HistogramModels {
                observe: record.observe.clone(),
                vlan: record.vlan,
                proto: record.proto.clone(),
                numerical: numerical_map,
                numeric_category: numerical_cat_map,
                string_category: string_cat_map,
                ipaddr_category: ipadd_cat_map,
                time_category: time_category_map,
                low: 0.0,
                medium: 0.0,
                high: 0.0,
                severe: 0.0,
            };
            let _ = model
                .build(&parquet_list, &self.feature_list)
                .map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("build error: {}", e))
                })?;
            distinct_models.insert(distinct_key, model);
        }
        println!("{}: done", self.command);

        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        let tmp_output = format!(
            "{}.{}.tmp",
            self.model_list[0],
            rfc3339_name.replace(":", "-")
        );
        let mut db_output = duckdb_open(&tmp_output, 1)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        // serialize to duckdb
        for (distinct_key, model) in distinct_models.iter() {
            println!(
                "{}: serializing HBOS model [{}]",
                self.command, distinct_key
            );
            let _ = model.serialize(&mut db_output).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("serialize error: {}", e))
            })?;
        }
        println!("{}: done", self.command);

        // summarize hbos
        for (distinct_key, model) in distinct_models.iter_mut() {
            println!(
                "{}: calculating HBOS summary [{}]",
                self.command, distinct_key
            );
            let _ = model
                .summarize(&parquet_list, &mut db_output)
                .map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("summarize error: {}", e))
                })?;
        }
        let _ = db_output
            .close()
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {:?}", e)))?;
        println!("{}: done", self.command);

        if Path::new(&self.model_list[0]).exists() {
            // backup the old model file
            let current_utc: DateTime<Utc> = Utc::now();
            let rfc3339_name: String = current_utc.to_rfc3339();
            let backup_file = format!("{}.{}", self.model_list[0], rfc3339_name.replace(":", "-"));
            fs::rename(&self.model_list[0], &backup_file).map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to rename backup model: {}", e),
                )
            })?;
        }

        if Path::new(&tmp_output).exists() {
            fs::rename(&tmp_output, &self.model_list[0]).map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to rename model: {}", e),
                )
            })?;

            // upload the model to motherduck if configured
            //self.upload_model(&self.model_list[0])?;
        }

        Ok(())
    }
}
