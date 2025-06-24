/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

extern crate exitcode;

use crate::utils::duckdb::{duckdb_open, duckdb_open_memory, duckdb_open_readonly};
use duckdb::Connection;
use serde::{Deserialize, Serialize};
use std::fs;

use chrono::{DateTime, TimeZone, Utc};
use std::time::SystemTime;

use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::FileType;
use crate::pipeline::Interval;
use std::io::Error;

pub const TAG_LIMIT: u8 = 8;

#[derive(Clone, Serialize, Deserialize)]
pub struct TagStructure {
    tag: String,
    #[serde(skip)]
    observe: Option<String>,
    #[serde(skip)]
    proto: Option<String>,
    #[serde(skip)]
    saddr: Option<String>,
    #[serde(default = "zero_port")]
    sport: Option<u16>,
    #[serde(skip)]
    daddr: Option<String>,
    #[serde(default = "zero_port")]
    dport: Option<u16>,
    #[serde(skip)]
    ndpi_appid: Option<String>,
    #[serde(skip)]
    orient: Option<String>,
}

fn zero_port() -> Option<u16> {
    Some(0)
}

pub struct TagProcessor {
    pub command: String,
    pub input: String,
    pub output: String,
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
        let interval = parse_interval(interval_string);
        let options = parse_options(options_string);
        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}={}]", command, key, value);
            }
        }
        let rule_file = options.get("tag").expect("expected tag file").to_string();

        let tag_list = TagProcessor::load_tag_file(&rule_file);

        Ok(Self {
            command: command.to_string(),
            input: input.to_string(),
            output: output.to_string(),
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

            if let Some(observe) = rule.observe {
                rule_command.push_str("AND observe ^@ '");
                rule_command.push_str(&observe);
                rule_command.push_str("'");
            }

            if let Some(proto) = rule.proto {
                rule_command.push_str("AND proto = '");
                rule_command.push_str(&proto);
                rule_command.push_str("'");
            }

            if let Some(saddr) = rule.saddr {
                rule_command.push_str("AND saddr ^@ '");
                rule_command.push_str(&saddr);
                rule_command.push_str("'");
            }

            if let Some(sport) = rule.sport {
                rule_command.push_str("AND sport = ");
                rule_command.push_str(&sport.to_string());
            }

            if let Some(daddr) = rule.daddr {
                rule_command.push_str("AND daddr ^@ '");
                rule_command.push_str(&daddr);
                rule_command.push_str("'");
            }

            if let Some(dport) = rule.dport {
                rule_command.push_str("AND dport = ");
                rule_command.push_str(&dport.to_string());
            }

            if let Some(ndpi_appid) = rule.ndpi_appid {
                rule_command.push_str("AND ndpi_appid ^@ '");
                rule_command.push_str(&ndpi_appid);
                rule_command.push_str("'");
            }

            if let Some(orient) = rule.orient {
                rule_command.push_str("AND orient ^@ '");
                rule_command.push_str(&orient);
                rule_command.push_str("'");
            }

            tag_rules.push(rule_command);
        }

        println!(".done.");
        tag_rules
    }

    fn export_parquet_file(&self, conn: &Connection) {
        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        let safe_rfc3339 = rfc3339_name.replace(":", "-");
        let tmp_filename = format!(".gnat-{}-{}.parquet", self.command, safe_rfc3339);
        let final_filename = format!("{}/{}", self.output, tmp_filename.trim_start_matches('.'));
        let sql_command = format!(
            "COPY (SELECT * FROM flow) TO '{}' (FORMAT 'parquet', CODEC 'snappy', ROW_GROUP_SIZE 100_000);",
            tmp_filename
        );
        conn.execute_batch(&sql_command).expect("sql batch");
        fs::rename(&tmp_filename, &final_filename).expect("renaming");
    }
}

impl FileProcessor for TagProcessor {
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
        let parquet_list = file_list
            .iter()
            .map(|file| format!("'{}'", file))
            .collect::<Vec<_>>()
            .join(",");
        let parquet_list = format!("[{}]", parquet_list);

        let mem_conn = duckdb_open_memory(2);
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

        self.export_parquet_file(&mem_conn);

        Ok(())
    }
}
