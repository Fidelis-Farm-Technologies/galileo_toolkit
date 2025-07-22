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
use crate::model::table::NumericCategoryRecord;
use crate::model::table::{HistogramSummaryTable, NumericHistogramTable};
use std::io::Error;

use crate::model::table::MemFlowRecord;
use duckdb::{params, Appender, Connection, DropBehavior};
use std::collections::HashMap;

#[derive(Debug)]
pub struct NumericCategoryHistogram {
    name: String,
    hash_size: i64,
    count: usize,
    filter: String,
    map: HashMap<i64, i64>,
}

impl NumericCategoryHistogram {
    pub fn new(name: &str, hash_size: i64, filter: &str) -> NumericCategoryHistogram {
        NumericCategoryHistogram {
            name: name.to_string(),
            hash_size,
            count: 0,
            filter: filter.to_string(),
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
                "numeric_category",
                self.count,
                self.hash_size,
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
    fn add(&mut self, value: i64) {
        let mut key = value;
        if self.hash_size != NO_MODULUS {
            key = value.rem_euclid(self.hash_size);
        }
        let value = self.map.entry(key).or_insert(0);
        *value += 1;
        self.count += 1;
    }
    pub fn probability(&self, value: i64) -> f64 {
        let mut key = value;
        if self.hash_size != NO_MODULUS {
            key = value.rem_euclid(self.hash_size);
        }
        if let Some(frequency) = self.map.get(&key) {
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
            "SELECT {} FROM flow WHERE {};",
            self.name, self.filter
        );
        let mut stmt = db.prepare(&sql_command)?;

        let record_iter = stmt.query_map([], |row| {
            Ok(NumericCategoryRecord {
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
        conn.execute_batch(HISTOGRAM_NUMERIC_CATEGORY).unwrap();

        let mut tx = conn.transaction().unwrap();
        tx.set_drop_behavior(DropBehavior::Commit);

        let mut appender: Appender = tx
            .appender("histogram_summary")
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        let _ = self.serialize_summary(&mut appender, observe, vlan, proto);

        let mut appender: Appender = tx
            .appender("histogram_numeric_category")
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
    ) -> NumericCategoryHistogram {
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

        let map: HashMap<i64, i64> = HashMap::new();
        let mut histogram_category = NumericCategoryHistogram {
            name: summary.name,
            hash_size: summary.hash_size as i64,
            count: summary.count,
            filter: summary.filter,
            map,
        };

        //
        //
        //
        let sql_command = format!(
            "SELECT * FROM histogram_numeric_category WHERE observe='{}' AND vlan = {} AND proto='{}' AND name='{}';",
            observe, vlan, proto, name
        );
        let mut stmt = db
            .prepare(&sql_command)
            .expect("histogram_numeric_category load");

        let histogram_iter = stmt
            .query_map([], |row| {
                Ok(NumericHistogramTable {
                    observe: row.get(0).expect("missing obseve"),
                    vlan: row.get(1).expect("missing vlan"),
                    proto: row.get(2).expect("missing proto"),
                    name: row.get(3).expect("missing name"),
                    key: row.get(4).expect("missing bin"),
                    value: row.get(5).expect("missing value"),
                })
            })
            .unwrap();

        for histogram in histogram_iter {
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
            "sport" => self.probability(record.sport as i64),
            "dport" => self.probability(record.dport as i64),
            "sentropy" => self.probability(record.sentropy as i64),
            "dentropy" => self.probability(record.dentropy as i64),
            "dvlan" => self.probability(record.dvlan as i64),
            "sasn" => self.probability(record.sasn as i64),
            "dasn" => self.probability(record.dasn as i64),
            "pcr" => self.probability(record.pcr as i64),
            _ => panic!("invalid feature"),
        }
    }
}
