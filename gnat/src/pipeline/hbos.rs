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
use crate::model::histogram::{MODEL_DISTINCT_OBSERVATIONS, PARQUET_DISTINCT_OBSERVATIONS};
use crate::model::table::DistinctObservation;
use crate::model::table::HbosSummaryRecord;
use crate::utils::duckdb::{duckdb_open, duckdb_open_memory, duckdb_open_readonly};
use chrono::{DateTime, TimeZone, Utc};
use duckdb::params;
use duckdb::Appender;
use duckdb::Connection;
use duckdb::DropBehavior;
use std::collections::HashMap;
use std::fs;
use std::io::Error;
use std::path::Path;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::FileType;
use crate::pipeline::Interval;

pub struct HbosProcessor {
    pub command: String,
    pub input: String,
    pub output: String,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
    pub model_spec: String,
    pub model_mtime: u64,
    pub hbos_summary_map: HashMap<String, HbosSummaryRecord>,
    pub histogram_map: HashMap<String, HistogramModels>,
}

impl HbosProcessor {
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

        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}={}]", command, key, value);
            }
        }

        let model_file = options
            .get("model")
            .expect("expected --option model=file")
            .to_string();

        let mtime = HbosProcessor::file_modified_time_in_seconds(&model_file);

        Ok(Self {
            command: command.to_string(),
            input: input.to_string(),
            output: output.to_string(),
            pass: pass.to_string(),
            interval,
            extension: extension_string.to_string(),
            model_spec: model_file,
            model_mtime: mtime,
            hbos_summary_map: HashMap::new(),
            histogram_map: HashMap::new(),
        })
    }
    pub fn file_modified_time_in_seconds(path: &str) -> u64 {
        if !Path::new(path).exists() {
            return 0;
        }
        match fs::metadata(path)
            .and_then(|meta| meta.modified())
            .and_then(|mtime| Ok(mtime.duration_since(UNIX_EPOCH)))
        {
            Ok(duration) => duration.expect("as secs").as_secs(),
            Err(_) => 0,
        }
    }
    fn load_hbos_summary(&mut self) -> Result<(), Error> {
        if !Path::new(&self.model_spec).exists() {
            let error_msg = format!(
                "{}: model file {} does not exist",
                self.command, self.model_spec
            );
            return Err(Error::other(error_msg));
        }

        let model_conn = duckdb_open_readonly(&self.model_spec, 2);

        let mut stmt = model_conn
            .prepare(MODEL_DISTINCT_OBSERVATIONS)
            .expect("sql prepare");

        let record_iter = stmt
            .query_map([], |row| {
                Ok(DistinctObservation {
                    observe: row.get(0).expect("missing value"),
                    vlan: row.get(1).expect("missing dvlan"),
                    proto: row.get(2).expect("missing proto"),
                })
            })
            .expect("query map");

        let mut distinct_observation_models: Vec<DistinctObservation> = Vec::new();
        for record in record_iter {
            distinct_observation_models.push(record.expect("unwrapping DistinctObservation"));
        }

        let mut hbos_summary_map: HashMap<String, HbosSummaryRecord> = HashMap::new();
        for record in distinct_observation_models.clone().into_iter() {
            let distinct_key = format!("{}/{}/{}", record.observe, record.vlan, record.proto);

            let sql_command = format!(
                "SELECT * FROM hbos_summary WHERE observe='{}' AND vlan = {} AND proto='{}';",
                record.observe, record.vlan, record.proto
            );
            let mut stmt = model_conn.prepare(&sql_command).expect("hbos_summary");
            let hbos_summary = stmt
                .query_row([], |row| {
                    Ok(HbosSummaryRecord {
                        observe: row.get(0).expect("missing value"),
                        vlan: row.get(1).expect("missing value"),
                        proto: row.get(2).expect("missing value"),
                        min: row.get(3).expect("missing value"),
                        max: row.get(4).expect("missing value"),
                        skewness: row.get(5).expect("missing value"),
                        avg: row.get(6).expect("missing value"),
                        std: row.get(7).expect("missing value"),
                        mad: row.get(8).expect("missing value"),
                        median: row.get(9).expect("missing value"),
                        quantile: row.get(10).expect("quantile value"),
                        low: row.get(11).expect("quantile value"),
                        medium: row.get(12).expect("quantile value"),
                        high: row.get(13).expect("quantile value"),
                    })
                })
                .expect("query row");

            hbos_summary_map.insert(distinct_key, hbos_summary);
        }

        let _ = model_conn.close();

        self.hbos_summary_map = hbos_summary_map;

        Ok(())
    }

    fn load_model(&mut self) -> Result<(), Error> {
        if !Path::new(&self.model_spec).exists() {
            let error_msg = format!(
                "{}: model file {} does not exist",
                self.command, self.model_spec
            );
            return Err(Error::other(error_msg));
        }
        let mut model_conn = duckdb_open_readonly(&self.model_spec, 2);
        let mut stmt = model_conn
            .prepare(MODEL_DISTINCT_OBSERVATIONS)
            .expect("sql prepare");

        let record_iter = stmt
            .query_map([], |row| {
                Ok(DistinctObservation {
                    observe: row.get(0).expect("missing value"),
                    vlan: row.get(1).expect("missing dvlan"),
                    proto: row.get(2).expect("missing proto"),
                })
            })
            .expect("query map");

        let mut distinct_observation: Vec<DistinctObservation> = Vec::new();
        for record in record_iter {
            distinct_observation.push(record.expect("unwrapping DistinctObservation"));
        }

        let mut distinct_models = HashMap::new();
        for record in distinct_observation.clone().into_iter() {
            let distinct_key = format!("{}/{}/{}", record.observe, record.vlan, record.proto);
            println!("hbos: loading histogram [{}]", distinct_key);

            let numerical_map: HashMap<String, NumberHistogram> = HashMap::new();
            let numerical_cat_map: HashMap<String, NumericCategoryHistogram> = HashMap::new();
            let string_cat_map: HashMap<String, StringCategoryHistogram> = HashMap::new();
            let ipadd_cat_map: HashMap<String, IpAddrCategoryHistogram> = HashMap::new();
            let time_category_map: HashMap<String, TimeCategoryHistogram> = HashMap::new();

            let mut model = HistogramModels {
                observe: record.observe,
                vlan: record.vlan,
                proto: record.proto,
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

            let _ = model.deserialize(&mut model_conn);
            let _ = distinct_models.insert(distinct_key, model);
        }
        let _ = model_conn.close();
        self.histogram_map = distinct_models;

        Ok(())
    }
    fn load_if_not_already(&mut self) -> Result<(), Error> {
        if self.hbos_summary_map.len() == 0 {
            match self.load_hbos_summary() {
                Ok(_) => println!("{}: loaded trigger table schema", self.command),
                Err(e) => return Err(e),
            }
        }
        if self.histogram_map.len() == 0 {
            match self.load_model() {
                Ok(_) => println!("{}: loaded model", self.command),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
impl FileProcessor for HbosProcessor {
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
        // Use iterator and join for file list formatting
        let parquet_list = file_list
            .iter()
            .map(|file| format!("'{}'", file))
            .collect::<Vec<_>>()
            .join(",");
        let parquet_list = format!("[{}]", parquet_list);

        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        // Sanitize rfc3339_name for filesystem safety
        let safe_rfc3339 = rfc3339_name.replace(":", "-");
        let tmp_filename = format!(".gnat_{}-{}.parquet", self.command, safe_rfc3339);
        let final_filename = format!("{}/{}", self.output, tmp_filename.trim_start_matches('.'));

        let mut db_out = duckdb_open_memory(2);

        match self.load_if_not_already() {
            Err(e) => {
                println!("{}: {}", self.command, e);
                let sql_command = format!(
                    "COPY (SELECT * FROM read_parquet({})) TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
                    parquet_list, tmp_filename
                );
                db_out.execute_batch(&sql_command).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;
                fs::rename(&tmp_filename, &final_filename)?;
                return Ok(());
            }
            _ => {}
        }

        {
            let mut db_in = duckdb_open_memory(2);
            let sql_command = format!(
                "CREATE TABLE flow AS SELECT * FROM read_parquet({});",
                parquet_list
            );
            db_in.execute_batch(&sql_command).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;

            println!("{}: determining observation points...", self.command);
            let mut stmt = db_in.prepare(PARQUET_DISTINCT_OBSERVATIONS).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;

            let record_iter = stmt
                .query_map([], |row| {
                    Ok(DistinctObservation {
                        observe: row.get(0).expect("missing value"),
                        vlan: row.get(1).expect("missing dvlan"),
                        proto: row.get(2).expect("missing proto"),
                    })
                })
                .map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;

            let mut distinct_observation_models: Vec<DistinctObservation> = Vec::new();
            for record in record_iter {
                distinct_observation_models.push(record.map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?);
            }

            println!("{}: scoring...", self.command);
            for record in &distinct_observation_models {
                let distinct_key = format!("{}/{}/{}", record.observe, record.vlan, record.proto);
                println!("{}:\t{}", self.command, distinct_key);
                let histogram_model = match self.histogram_map.get_mut(&distinct_key) {
                    None => {
                        eprintln!("Warning: missing histogram model {}", distinct_key);
                        continue;
                    }
                    Some(model) => model,
                };
                let _ = histogram_model.score(&mut db_in, &mut db_out);
            }
        }

        println!("{}: transforming data...", self.command);
        let sql_transform_command = format!(
            "CREATE OR REPLACE TABLE flow AS SELECT * FROM read_parquet({});
             UPDATE flow SET hbos_score = score_table.hbos_score FROM score_table WHERE flow.id = score_table.id;
             COPY (SELECT * FROM flow) TO '{}' (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 100_000);",
            parquet_list, tmp_filename
        );

        db_out
            .execute_batch(&sql_transform_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        let _ = db_out.close();

        fs::rename(&tmp_filename, &final_filename)?;

        if Path::new(&self.model_spec).exists() {
            let mtime = HbosProcessor::file_modified_time_in_seconds(&self.model_spec);
            if mtime != self.model_mtime {
                println!("{}: (re)loading new model...", self.command);
                self.model_mtime = mtime;
                self.hbos_summary_map.clear();
                self.histogram_map.clear();
            }
        }

        Ok(())
    }
}
