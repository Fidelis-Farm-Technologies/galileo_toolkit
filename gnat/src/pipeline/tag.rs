/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

extern crate exitcode;

use crate::pipeline::StreamType;

use crate::pipeline::check_parquet_stream;
use crate::utils::duckdb::duckdb_open_memory;
use duckdb::Connection;
use serde::{Deserialize, Serialize};
use std::fs;

use chrono::{DateTime, Utc};

use crate::pipeline::load_environment;
use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::Interval;
use std::io::Error;

pub const TAG_LIMIT: u8 = 16;

#[derive(Clone, Serialize, Deserialize)]
pub struct TagStructure {
    tag: String,
    #[serde(default = "default_string")]
    observe: String,
    #[serde(default = "default_string")]
    proto: String,
    #[serde(default = "default_string")]
    saddr: String,
    #[serde(default = "zero_port")]
    sport: u16,
    #[serde(default = "default_string")]
    daddr: String,
    #[serde(default = "zero_port")]
    dport: u16,
    #[serde(default = "default_string")]
    ndpi_appid: String,
    #[serde(default = "default_string")]
    orient: String,
}

fn zero_port() -> u16 {
    0
}

fn default_string() -> String {
    "".to_owned()
}

pub struct TagProcessor {
    pub command: String,
    pub input_list: Vec<String>,
    pub output_list: Vec<String>,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
    pub tag_list: Vec<String>,
}

impl TagProcessor {
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
        let options = parse_options(options_string);
        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}=>{}]", command, key, value);
            }
        }
        let rule_file = options.get("tag").expect("expected tag file").to_string();

        let tag_list = TagProcessor::load_tag_file(&rule_file);

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
            tag_list: tag_list,
        })
    }

    fn load_tag_file(rule_spec: &String) -> Vec<String> {
        let json_data: String = fs::read_to_string(rule_spec).expect("unable to read JSON file");
        let tag_list: Vec<TagStructure> =
            serde_json::from_str(&json_data).expect("failed to parse tag file");

        println!("Loading tag file...");
        let mut tag_rules: Vec<String> = Vec::new();

        for rule in tag_list.clone().into_iter() {
            let mut rule_command = format!(
                "SET tag = list_concat(tag, ['{}']) WHERE tag IS NULL OR NOT list_has_any(tag,['{}'])",
                rule.tag,  rule.tag
            );

            if !rule.observe.is_empty() {
                rule_command.push_str("AND observe ^@ '");
                rule_command.push_str(&rule.observe);
                rule_command.push_str("' ");
            }

            if !rule.proto.is_empty() {
                rule_command.push_str("AND proto = '");
                rule_command.push_str(&rule.proto);
                rule_command.push_str("' ");
            }

            if !rule.saddr.is_empty() {
                rule_command.push_str("AND saddr ^@ '");
                rule_command.push_str(&rule.saddr);
                rule_command.push_str("' ");
            }

            if rule.sport != 0 {
                rule_command.push_str("AND sport = ");
                rule_command.push_str(&rule.sport.to_string());
                rule_command.push_str(" ");
            }

            if !rule.daddr.is_empty() {
                rule_command.push_str("AND daddr ^@ '");
                rule_command.push_str(&rule.daddr);
                rule_command.push_str("' ");
            }

            if rule.dport != 0 {
                rule_command.push_str("AND dport = ");
                rule_command.push_str(&rule.dport.to_string());
                rule_command.push_str(" ");
            }

            if !rule.ndpi_appid.is_empty() {
                rule_command.push_str("AND ndpi_appid ^@ '");
                rule_command.push_str(&rule.ndpi_appid);
                rule_command.push_str("' ");
            }

            if !rule.orient.is_empty() {
                rule_command.push_str("AND orient ^@ '");
                rule_command.push_str(&rule.orient);
                rule_command.push_str("' ");
            }

            //println!("tag rule: {}", rule_command);

            tag_rules.push(rule_command);
        }

        println!(".done.");
        tag_rules
    }

    fn export_parquet_file(&self, conn: &Connection) -> Result<(), Error> {
        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        let safe_rfc3339 = rfc3339_name.replace(":", "-");
        let tmp_filename = format!(
            "{}/.gnat-{}-{}.parquet",
            self.output_list[0], self.command, safe_rfc3339
        );
        let final_filename = format!(
            "{}/gnat-{}-{}.parquet",
            self.output_list[0], self.command, safe_rfc3339
        );
        let sql_command = format!(
            "COPY (SELECT * FROM flow) TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
            tmp_filename
        );
        conn.execute_batch(&sql_command).expect("sql batch");
        fs::rename(&tmp_filename, &final_filename).expect("renaming");

        Ok(())
    }
}

impl FileProcessor for TagProcessor {
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
        let mem_conn = duckdb_open_memory(1)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        let sql_command = format!(
            "CREATE TABLE flow AS SELECT * FROM read_parquet({})",
            parquet_list
        );
        mem_conn
            .execute_batch(&sql_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        for rule in &self.tag_list {
            let sql_command = format!("UPDATE flow {};", rule);
            mem_conn.execute_batch(&sql_command).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;
        }

        let _ = self.export_parquet_file(&mem_conn);

        Ok(())
    }
}
