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

use crate::model::histogram::PARQUET_DISTINCT_OBSERVATIONS;
use crate::model::table::DistinctObservation;
use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::Interval;
use crate::pipeline::FileType;
use chrono::Datelike;
use chrono::{DateTime, TimeZone, Utc};
use std::time::UNIX_EPOCH;

use crate::utils::duckdb::{duckdb_open, duckdb_open_memory};

use std::collections::HashMap;
use std::fs;
use std::io::Error;
use std::path::Path;
use std::time::SystemTime;

pub struct ModelProcessor {
    pub command: String,
    pub input: String,
    pub model: String,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
    pub feature_list: Vec<String>,
    pub quantile: f64,
    pub name: String,
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
        let interval = parse_interval(interval_string);
        let mut options = parse_options(options_string);
        options.entry("name").or_insert("hbos");
        options
            .entry("features")
            .or_insert("daddr,dport,dentropy,sentropy,diat,siat,spd,pcr,orient,stime");
        options.entry("quantile").or_insert("0.99999");

        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}={}]", command, key, value);
            }
        }
        let name = options.get("name").expect("expected name");
        let features = options.get("features").expect("expected feature");
        let feature_list: Vec<String> = features.split(",").map(str::to_string).collect();
        let quantile = options
            .get("quantile")
            .expect("expected quantile")
            .parse::<f64>()
            .unwrap();

        if quantile >= 1.0 || quantile <= 0.0 {
            return Err(Error::other("quantile option must be 0.0 < x < 1.0"));
        }
        Ok(Self {
            command: command.to_string(),
            input: input.to_string(),
            model: output.to_string(),
            pass: pass.to_string(),
            interval: interval,
            extension: extension_string.to_string(),
            feature_list: feature_list,
            quantile: quantile,
            name: name.to_string(),
        })
    }
}
impl FileProcessor for ModelProcessor {
    fn get_command(&self) -> &String {
        &self.command
    }
    fn get_input(&self) -> &String {
        &self.input
    }
    fn get_output(&self) -> &String {
        &self.model
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
        false
    }
    fn process(&mut self, file_list: &Vec<String>,  _schema_type: FileType) -> Result<(), Error> {
        if Path::new(&self.model).exists() {
            if self.interval != Interval::ONCE {
                // check if the current model is a day old, if so build a new one
                let meta = fs::metadata(&self.model)
                    .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("failed to get metadata: {}", e)))?;
                let ctime_local = meta.created()
                    .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("failed to get created time: {}", e)))?;
                let ctime_utc: DateTime<Utc> = ctime_local.into();
                if Utc::now().day() == ctime_utc.day() {
                    // no change
                    return Ok(());
                }
            }
        }

        let tmp_output = format!("{}.tmp", self.model);
        let mut db_conn = duckdb_open(&tmp_output, 2);
        let mut parquet_conn = duckdb_open_memory(2);

        // Use iterator and join for file list formatting
        let parquet_list = file_list
            .iter()
            .map(|file| format!("'{}'", file))
            .collect::<Vec<_>>()
            .join(",");
        let parquet_list = format!("[{}]", parquet_list);

        let sql_command = format!(
            "CREATE TABLE flow AS SELECT * FROM read_parquet({}) WHERE proto='udp' OR (proto='tcp' AND iflags ^@ 'Ss.a');",
            parquet_list
        );
        parquet_conn
            .execute_batch(&sql_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        // load observation list
        println!("{}: determining observation points...", self.command);
        let mut stmt = parquet_conn
            .prepare(PARQUET_DISTINCT_OBSERVATIONS)
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
            distinct_observation_models.push(record.map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?);
        }

        // build histograms
        let mut distinct_models = HashMap::new();
        for record in &distinct_observation_models {
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
                quantile: 0.0,
                low: 0.0,
                medium: 0.0,
                high: 0.0,
            };
            model.build(&parquet_conn, &self.feature_list);
            distinct_models.insert(distinct_key, model);
        }

        // serialize to duckdb
        for (distinct_key, model) in distinct_models.iter() {
            println!(
                "{}: serializing HBOS model [{}]",
                self.command, distinct_key
            );
            model.serialize(&mut db_conn);
        }

        // summarize hbos
        for (distinct_key, model) in distinct_models.iter_mut() {
            println!(
                "{}: calculating HBOS summary [{}]",
                self.command, distinct_key
            );
            model.summarize(&mut parquet_conn, &mut db_conn, self.quantile);
        }

        let _ = db_conn.close();
        let _ = parquet_conn.close();

        if Path::new(&self.model).exists() {
            // backup the old model file
            let current_utc: DateTime<Utc> = Utc::now();
            let rfc3339_name: String = current_utc.to_rfc3339();
            let backup_file = format!("{}.{}", self.model, rfc3339_name.replace(":", "-"));
            fs::rename(&self.model, &backup_file)
                .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("failed to rename backup model: {}", e)))?;
        }
        fs::rename(&tmp_output, &self.model)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("failed to rename model: {}", e)))?;
        Ok(())
    }
}
