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

use crate::pipeline::check_parquet_stream;
use crate::pipeline::load_environment;

use crate::pipeline::StreamType;
use crate::utils::duckdb::{duckdb_open_memory, duckdb_open_readonly};
use chrono::{DateTime, Utc};
use std::path::Path;

use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::fs;
use std::io::Error;

use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::Interval;

#[derive(Clone, Serialize, Deserialize)]
pub struct RuleJsonStructure {
    action: String,
    observe: String,
    #[serde(skip)]
    proto: String,
    #[serde(skip)]
    saddr: String,
    #[serde(skip)]
    sport: u16,
    #[serde(skip)]
    daddr: String,
    #[serde(skip)]
    dport: u16,
    #[serde(skip)]
    appid: String,
    #[serde(skip)]
    orient: String,
    #[serde(skip)]
    tag: String,
    #[serde(skip)]
    risk_severity: u8,
    #[serde(skip)]
    hbos_severity: u8,
}

pub struct RuleProcessor {
    pub command: String,
    pub input_list: Vec<String>,
    pub output_list: Vec<String>,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
    pub model_spec: String,
    pub rule_spec: String,
    pub rules: Vec<String>,
    pub histogram_map: HashMap<String, HistogramModels>,
    pub distinct_features: Vec<String>,
}

impl RuleProcessor {
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
        let options: HashMap<&str, &str> = parse_options(options_string);
        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}=>{}]", command, key, value);
            }
        }
        let model_file = options
            .get("model")
            .expect("expected --option model=file")
            .to_string();

        let rule_file = options.get("rule").expect("expected rule file").to_string();

        let rules: Vec<String> = Vec::new();
        let histogram_map: HashMap<String, HistogramModels> = HashMap::new();
        let distinct_features: Vec<String> = Vec::new();
        //let sql_table_schema = String::from("");

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
            rule_spec: rule_file,
            rules: rules,
            histogram_map: histogram_map,
            distinct_features: distinct_features,
        })
    }

    fn load_configuration(&mut self) -> Result<(), Error> {
        if !Path::new(&self.model_spec).exists() {
            let error_msg = format!(
                "{}: model file {} does not exist",
                self.command, self.model_spec
            );
            return Err(Error::other(error_msg));
        }
        if !Path::new(&self.rule_spec).exists() {
            let error_msg = format!(
                "{}: rule file {} does not exist",
                self.command, self.model_spec
            );
            return Err(Error::other(error_msg));
        }
        self.rules = RuleProcessor::load_rule_file(&self.rule_spec).expect("loading rule file");

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
            println!("rule: loading histogram [{}]", distinct_key);

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
                filter: "".to_string(),
            };

            let _ = model.deserialize(&mut model_conn);
            let _ = distinct_models.insert(distinct_key, model);
        }

        //
        // load the distinct features
        //
        let mut stmt = model_conn
            .prepare("select distinct name from histogram_summary;")
            .expect("sql prepare");
        let feature_iter = stmt
            .query_map([], |row| {
                Ok(row.get::<_, String>(0).expect("missing feature"))
            })
            .expect("expected query map");

        for element in feature_iter {
            self.distinct_features
                .push(element.expect("expected histogram"));
        }

        let _ = model_conn.close();

        self.histogram_map = distinct_models;

        Ok(())
    }

    fn load_rule_file(rule_spec: &str) -> Result<Vec<String>, Error> {
        let json_data: String = fs::read_to_string(rule_spec).expect("unable to read JSON file");
        let policies: Vec<RuleJsonStructure> =
            serde_json::from_str(&json_data).expect("failed to parse rule file");

        println!("Loading rule file...");
        let mut rules: Vec<String> = Vec::new();

        if policies.is_empty() {
            eprintln!("error: no policies found in rule file '{}'", rule_spec);
            std::process::exit(exitcode::CONFIG);
        }
        if policies.len() > 1000 {
            eprintln!(
                "warning: more than 1000 policies found in rule file '{}'",
                rule_spec
            );
        }
        println!("{} policies found", policies.len());
        let mut terms = 0;
        for rule in policies.clone().into_iter() {
            let mut rule_line = String::from("SET trigger = -1 WHERE ");
            if rule.action == "trigger" {
                rule_line = String::from("SET trigger = 1 WHERE ");
            } else if rule.action != "ignore" {
                return Err(Error::other(format!(
                    "error: 'action' invalid value '{}', only 'trigger' and 'ignore' are supported",
                    rule.action
                )));
            }

            if !rule.observe.is_empty() {
                rule_line.push_str("observe ^@ '");
                rule_line.push_str(&rule.observe);
                rule_line.push_str("'");
                terms += 1;
            }

            if !rule.proto.is_empty() {
                if terms > 0 {
                    rule_line.push_str(" AND ");
                }
                terms += 1;
                rule_line.push_str("proto = '");
                rule_line.push_str(&rule.proto);
                rule_line.push_str("'");
            }

            if !rule.saddr.is_empty() {
                if terms > 0 {
                    rule_line.push_str(" AND ");
                }
                terms += 1;
                rule_line.push_str("saddr ^@ '");
                rule_line.push_str(&rule.saddr);
                rule_line.push_str("'");
            }

            if rule.sport != 0 {
                if terms > 0 {
                    rule_line.push_str(" AND ");
                }
                terms += 1;
                rule_line.push_str("sport = ");
                rule_line.push_str(&rule.sport.to_string());
            }

            if !rule.daddr.is_empty() {
                if terms > 0 {
                    rule_line.push_str(" AND ");
                }
                terms += 1;
                rule_line.push_str("daddr ^@ '");
                rule_line.push_str(&rule.daddr);
                rule_line.push_str("'");
            }

            if rule.dport != 0 {
                if terms > 0 {
                    rule_line.push_str(" AND ");
                }
                terms += 1;
                rule_line.push_str("dport = ");
                rule_line.push_str(&rule.dport.to_string());
            }

            if !rule.appid.is_empty() {
                if terms > 0 {
                    rule_line.push_str(" AND ");
                }
                terms += 1;
                rule_line.push_str("ndpi_appid ^@ '");
                rule_line.push_str(&rule.appid);
                rule_line.push_str("'");
            }

            if !rule.orient.is_empty() {
                if terms > 0 {
                    rule_line.push_str(" AND ");
                }
                terms += 1;
                rule_line.push_str("orient ^@ '");
                rule_line.push_str(&rule.orient);
                rule_line.push_str("'");
            }

            if !rule.tag.is_empty() {
                if terms > 0 {
                    rule_line.push_str(" AND ");
                }
                terms += 1;
                rule_line.push_str("list_has_any(tag,['");
                rule_line.push_str(&rule.tag);
                rule_line.push_str("'])");
            }

            if rule.risk_severity != 0 {
                if terms > 0 {
                    rule_line.push_str(" AND ");
                }
                terms += 1;
                rule_line.push_str("ndpi_risk_severity >= ");
                rule_line.push_str(&rule.risk_severity.to_string());
            }

            if rule.hbos_severity != 0 {
                if terms > 0 {
                    rule_line.push_str(" AND ");
                }
                terms += 1;
                rule_line.push_str("hbos_severity >= ");
                rule_line.push_str(&rule.hbos_severity.to_string());
            }
            rules.push(rule_line);
        }

        println!(".done.");
        Ok(rules)
    }

    fn load_model(&mut self) -> Result<(), Error> {
        if self.histogram_map.len() == 0 {
            match self.load_configuration() {
                Ok(_) => println!("{}: loaded configuration", self.command),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
impl FileProcessor for RuleProcessor {
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
            let _ = self.forward(&parquet_list, &self.output_list.clone())?;
            return Ok(());
        }

        let mut db_in = duckdb_open_memory(2);
        let sql_command = format!(
            "CREATE TABLE flow AS SELECT * FROM read_parquet({});",
            parquet_list
        );
        db_in
            .execute_batch(&sql_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        // apply rules to the flow table
        println!("{}: applying {} rules...", self.command, self.rules.len());
        for rule in self.rules.iter() {
            let sql_command = format!("UPDATE flow {};", rule);
            db_in.execute_batch(&sql_command).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;
        }

        // load distinct observation models
        println!("{}: determining observation points...", self.command);
        let mut stmt = db_in
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

        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();

        let tmp_parquet_filename = format!(
            ".gnat-{}-{}.parquet",
            self.command,
            rfc3339_name.replace(":", "-")
        );
        let parquet_filename = format!(
            "{}/gnat-{}-{}.parquet",
            self.output_list[0],
            self.command,
            rfc3339_name.replace(":", "-")
        );

        println!("{}: processing...", self.command);

        let mut db_out = duckdb_open_memory(2);
        let mut trigger_count = 0;
        {
            db_out.execute_batch("CREATE TABLE trigger_table (id UUID,trigger TINYINT,risk_list VARCHAR[],hbos_map map(VARCHAR,DOUBLE));")
                .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
            for record in &distinct_observation_models {
                let distinct_key = format!("{}/{}/{}", record.observe, record.vlan, record.proto);
                let histogram_model =
                    self.histogram_map.get_mut(&distinct_key).ok_or_else(|| {
                        Error::new(
                            std::io::ErrorKind::Other,
                            format!("missing histogram model: {}", distinct_key),
                        )
                    })?;
                let triggers = histogram_model
                    .generate_trigger_data(&mut db_in, &mut db_out)
                    .map_err(|e| {
                        Error::new(
                            std::io::ErrorKind::Other,
                            format!("generate_trigger_data error: {}", e),
                        )
                    })?;
                if triggers > 0 {
                    println!("{}: [{}] {} triggers", self.command, distinct_key, triggers);
                }
                trigger_count += triggers;
            }
        }
        let _ = db_in.close();

        if trigger_count > 0 {
            println!("{}: transforming data...", self.command);
            let sql_transform_command = format!(
                "CREATE TABLE flow AS SELECT * FROM read_parquet({});
                 UPDATE flow
                   SET trigger = flow_meta.trigger,ndpi_risk_list = flow_meta.risk_list,hbos_map = flow_meta.hbos_map
                   FROM flow_meta
                   WHERE flow.id = flow_meta.id;
                 COPY (SELECT * FROM flow) TO '{}' (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 100_000);",
                parquet_list, tmp_parquet_filename
            );
            db_out.execute_batch(&sql_transform_command).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;
        } else {
            let sql_command = format!(
                "COPY (SELECT * FROM read_parquet({})) TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
                parquet_list, tmp_parquet_filename
            );
            db_out.execute_batch(&sql_command).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;
        }
        let _ = db_out.close();

        fs::rename(&tmp_parquet_filename, &parquet_filename).map_err(|e| {
            Error::new(
                std::io::ErrorKind::Other,
                format!("renaming temporary file error: {}", e),
            )
        })?;

        Ok(())
    }
}
