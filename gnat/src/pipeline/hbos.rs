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

use crate::pipeline::check_parquet_stream;
use crate::pipeline::load_environment;
use crate::pipeline::StreamType;
use crate::utils::duckdb::{duckdb_open_memory, duckdb_open_readonly};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::fs;
use std::io::Error;
use std::path::Path;
use std::time::UNIX_EPOCH;

use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::Interval;

pub struct HbosProcessor {
    pub command: String,
    pub input_list: Vec<String>,
    pub output_list: Vec<String>,
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
        let _ = load_environment();
        let interval = parse_interval(interval_string);
        let options = parse_options(options_string);

        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}=>{}]", command, key, value);
            }
        }

        let model_file = options
            .get("model")
            .expect("expected --option model=file")
            .to_string();

        let mtime = HbosProcessor::file_modified_time_in_seconds(&model_file);

        let mut input_list = Vec::<String>::new();
        input_list.push(input.to_string());
        let mut output_list = Vec::<String>::new();
        output_list.push(output.to_string());
        Ok(Self {
            command: command.to_string(),
            input_list: input_list,
            output_list: output_list,
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

        println!("{}: loading hbos summary information", self.command);
        let model_conn = duckdb_open_readonly(&self.model_spec, 1)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        let mut stmt = model_conn
            .prepare(MODEL_DISTINCT_OBSERVATIONS)
            .map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("DuckDB prepare error: {}", e),
                )
            })?;

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
                        quantile: row.get(10).expect("missing value"),
                        low: row.get(11).expect("missing value"),
                        medium: row.get(12).expect("missing value"),
                        high: row.get(13).expect("missing value"),
                        severe: row.get(14).expect("missing value"),
                    })
                })
                .expect("query row");

            hbos_summary_map.insert(distinct_key, hbos_summary);
        }

        let _ = model_conn.close();

        self.hbos_summary_map = hbos_summary_map;

        Ok(())
    }

    fn load_hbos_model(&mut self) -> Result<(), Error> {
        if !Path::new(&self.model_spec).exists() {
            let error_msg = format!(
                "{}: model file {} does not exist",
                self.command, self.model_spec
            );
            return Err(Error::other(error_msg));
        }
        println!("{}: loading hbos model information", self.command);
        let mut model_conn = duckdb_open_readonly(&self.model_spec, 1)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
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
                low: 0.0,
                medium: 0.0,
                high: 0.0,
                severe: 0.0,
            };

            let _ = model.deserialize(&mut model_conn);
            println!(
                "{}: low={}, medium={}, high={}, severe={}",
                self.command, model.low, model.medium, model.high, model.severe
            );
            let _ = distinct_models.insert(distinct_key, model);
        }
        let _ = model_conn.close();
        self.histogram_map = distinct_models;

        Ok(())
    }
    fn load_model(&mut self) -> Result<(), Error> {
        if self.hbos_summary_map.len() == 0 {
            match self.load_hbos_summary() {
                Ok(_) => println!("{}: loaded trigger table schema", self.command),
                Err(e) => return Err(e),
            }
        }
        if self.histogram_map.len() == 0 {
            match self.load_hbos_model() {
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

        if let Err(_e) = self.load_model() {
            // If loading the model fails,
            // it is because the model db does not exit,
            // therefore, just forward the data
            println!("{}: model does not exists; skipping...", self.command);
            let _ = self.forward(&parquet_list, &self.output_list.clone());
            return Ok(());
        }

        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        // Sanitize rfc3339_name for filesystem safety
        let safe_rfc3339 = rfc3339_name.replace(":", "-");
        let tmp_filename = format!(
            "{}/.gnat_{}-{}.parquet",
            self.output_list[0], self.command, safe_rfc3339
        );
        let final_filename = format!(
            "{}/gnat_{}-{}.parquet",
            self.output_list[0], self.command, safe_rfc3339
        );

        let mut db_conn = duckdb_open_memory(1)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        db_conn
            .execute_batch("CREATE TABLE score_table (id UUID, hbos_score DOUBLE, hbos_severity UTINYINT);").        
        map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        db_conn
            .execute_batch("CREATE TABLE hbos_map_table (id UUID,risk_list VARCHAR[],hbos_map map(VARCHAR,DOUBLE));")
                .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        let sql_command = format!(
            "CREATE TABLE flow AS SELECT * FROM read_parquet({});",
            parquet_list
        );
        db_conn
            .execute_batch(&sql_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        println!("{}: determining observation points...", self.command);
        let mut stmt = db_conn
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

            let _ = histogram_model.score(&mut db_conn).map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("hbos scoring error: {}", e),
                )
            })?;
        }

        //
        // Update the flow table with the hbos scores and severity
        //
        println!("{}: updating records...", self.command);
        let sql_transform_command = format!(
            "UPDATE flow 
                SET hbos_score = score_table.hbos_score, hbos_severity = score_table.hbos_severity
                FROM score_table WHERE flow.id = score_table.id;
            UPDATE flow 
                SET hbos_map = hbos_map_table.hbos_map, ndpi_risk_list = hbos_map_table.risk_list 
                FROM hbos_map_table WHERE flow.id = hbos_map_table.id;"
        );

        db_conn
            .execute_batch(&sql_transform_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        //
        // Export the flow table to parquet
        //
        let sql_export_command = format!(
            "COPY (SELECT * FROM flow) TO '{}' (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 100_000);",
            tmp_filename
            );
        db_conn
            .execute_batch(&sql_export_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        let _ = db_conn.close();

        if Path::new(&tmp_filename).exists() {
            fs::rename(&tmp_filename, &final_filename)?;
        }

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
