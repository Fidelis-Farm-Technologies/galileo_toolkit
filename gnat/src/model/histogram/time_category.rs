/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */
use crate::model::histogram::HistogramType;
use crate::model::histogram::HistogramType::*;
use crate::model::histogram::*;
use crate::model::table::MemFlowRecord;
use crate::model::table::TimeCategoryRecord;
use crate::model::table::{HistogramSummaryTable, TimeHistogramTable};
use chrono::prelude::*;
use chrono::{TimeZone, Utc};
use std::io::Error;

use duckdb::{params, Appender, Connection, DropBehavior};
use std::collections::HashMap;

#[derive(Debug)]
pub struct TimeCategoryHistogram {
    name: String,
    count: u64,
    filter: String,
    map: HashMap<u32, u64>,
}

impl TimeCategoryHistogram {
    pub fn new(name: &str, filter: &str) -> TimeCategoryHistogram {
        TimeCategoryHistogram {
            name: name.to_string(),
            count: 0,
            filter: String::new(),
            map: HashMap::new(),
        }
    }

    fn serialize_summary(
        &self,
        appender: &mut Appender,
        observe: &str,
        vlan: i64,
        proto: &str,
    ) -> Result<(), Error> {
        appender
            .append_row(params![
                observe,
                vlan,
                proto,
                self.name,
                "time_category",
                self.count,
                0,
                0,
                self.filter
            ])
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        Ok(())
    }
    fn serialize_histogram(
        &self,
        appender: &mut Appender,
        observe: &str,
        vlan: i64,
        proto: &str,
    ) -> Result<(), Error> {
        println!(
            "{}: serializing [{}/{}/{}/{}]...",
            self.name, observe, vlan, proto, self.name
        );
        for (hash_bin, value) in &self.map {
            appender
                .append_row(params![observe, vlan, proto, self.name, hash_bin, value])
                .map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;
        }

        Ok(())
    }
    fn add(&mut self, epoch_micros: u64) {
        let dt = Utc
            .timestamp_opt(
                (epoch_micros / 1_000_000) as i64,
                (epoch_micros % 1_000_000) as u32,
            )
            .unwrap();

        let bin_count = self.map.entry(dt.hour()).or_insert(0);
        *bin_count += 1;
        self.count += 1;
    }
    pub fn probability(&self, epoch_micros: u64) -> f64 {
        let dt = Utc
            .timestamp_opt(
                (epoch_micros / 1_000_000) as i64,
                (epoch_micros % 1_000_000) as u32,
            )
            .unwrap();

        if let Some(frequency) = self.map.get(&dt.hour()) {
            return (*frequency + 1) as f64 / (self.count as f64 + 1.0);
        }

        1.0 / (self.count as f64 + 1.0)
    }

    pub fn build(
        &mut self,
        db: &Connection,
        observe: &str,
        vlan: i64,
        proto: &str,
    ) -> Result<(), duckdb::Error> {
        let sql_command = format!(
            "SELECT {} FROM flow WHERE observe='{}' AND dvlan = {} AND proto='{}' AND {};",
            self.name, observe, vlan, proto, self.filter
        );
        let mut stmt = db.prepare(&sql_command)?;

        let record_iter = stmt.query_map([], |row| {
            Ok(TimeCategoryRecord {
                value: row.get(0).expect("missing value"),
            })
        })?;

        for record in record_iter {
            let record = record?;
            self.add(record.value);
        }
        Ok(())
    }
    pub fn serialize(
        &self,
        conn: &mut Connection,
        observe: &str,
        vlan: i64,
        proto: &str,
    ) -> Result<(), Error> {
        conn.execute_batch(HISTOGRAM_SUMMARY).unwrap();
        conn.execute_batch(HISTOGRAM_TIME_CATEGORY).unwrap();

        let mut tx = conn.transaction().unwrap();
        tx.set_drop_behavior(DropBehavior::Commit);
        let mut appender: Appender = tx
            .appender("histogram_summary")
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        let _ = self.serialize_summary(&mut appender, observe, vlan, proto);
        let mut appender: Appender = tx
            .appender("histogram_time_category")
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        let _ = self.serialize_histogram(&mut appender, observe, vlan, proto);
        Ok(())
    }
    pub fn load(
        db: &Connection,
        name: &str,
        observe: &str,
        vlan: i64,
        proto: &str,
    ) -> TimeCategoryHistogram {
        let sql_command = format!(
            "SELECT * FROM histogram_summary WHERE observe='{}' AND vlan = {} AND proto='{}' AND name='{}';",
            observe, vlan, proto, name
        );
        let mut stmt = db.prepare(&sql_command).expect("histogram_summary load");
        let summary = stmt
            .query_row([], |row| {
                Ok(HistogramSummaryTable {
                    observe: row.get(0).expect("missing obseve"),
                    vlan: row.get(1).expect("missing vlan"),
                    proto: row.get(2).expect("missing proto"),
                    name: row.get(3).expect("missing name"),
                    histogram: row.get(4).expect("missing histogram"),
                    count: row.get(5).expect("missing max"),
                    hash_size: row.get(6).expect("missing hash_size"),
                    bin_count: row.get(7).expect("missing bin_count"),
                    filter: row.get(8).expect("missing filter"),
                })
            })
            .unwrap();
        //
        //
        //
        let map: HashMap<u32, u64> = HashMap::new();
        let mut histogram_category = TimeCategoryHistogram {
            name: summary.name,
            count: summary.count as u64,
            filter: summary.filter,
            map,
        };
        //
        //
        //
        let sql_command = format!(
            "SELECT * FROM histogram_time_category WHERE observe='{}' AND vlan = {} AND proto='{}' AND name='{}';",
            observe, vlan, proto, name
        );
        let mut stmt = db
            .prepare(&sql_command)
            .expect("histogram_time_category load");

        let historgram_iter = stmt
            .query_map([], |row| {
                Ok(TimeHistogramTable {
                    observe: row.get(0).expect("missing obseve"),
                    vlan: row.get(1).expect("missing vlan"),
                    proto: row.get(2).expect("missing proto"),
                    name: row.get(3).expect("missing name"),
                    key: row.get(4).expect("missing bin"),
                    value: row.get(5).expect("missing value"),
                })
            })
            .unwrap();

        for histogram in historgram_iter {
            let record = histogram.unwrap();
            histogram_category.map.insert(record.key, record.value);
        }

        histogram_category
    }
    pub fn name(self) -> String {
        self.name
    }
    pub fn histogram_type(self) -> HistogramType {
        NumericCategory
    }
    pub fn get_probability(&mut self, record: &MemFlowRecord) -> f64 {
        match self.name.as_str() {
            "stime" => self.probability(record.stime),
            "etime" => self.probability(record.etime),
            _ => panic!("invalid feature"),
        }
    }
}
