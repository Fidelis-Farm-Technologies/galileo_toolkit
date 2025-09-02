/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */
use crate::model::histogram::*;
use crate::model::histogram::{HistogramType, HistogramType::StringCategory};
use crate::model::table::MemFlowRecord;
use crate::model::table::StringCategoryRecord;
use crate::model::table::{HistogramSummaryTable, StringHistogramTable};
use duckdb::{params, Appender, Connection, DropBehavior};
use std::collections::HashMap;
use std::io::Error;

#[derive(Debug)]
pub struct StringCategoryHistogram {
    name: String,
    count: usize,
    filter: String,
    map: HashMap<String, i64>,
}

impl StringCategoryHistogram {
    pub fn new(name: &String, filter: &str) -> StringCategoryHistogram {
        StringCategoryHistogram {
            name: name.to_string(),
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
                "string_category",
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
        for (key, value) in &self.map {
            //let normalized = *value / self.dport.count as u64;
            appender
                .append_row(params![observe, vlan, proto, self.name, key, value])
                .map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;
        }
        Ok(())
    }
    fn add(&mut self, key: &str) {
        let value = self.map.entry(key.to_string()).or_insert(0);
        *value += 1;
        self.count += 1;
    }
    pub fn probability(&self, key: &str) -> f64 {
        if let Some(frequency) = self.map.get(key) {
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
            "SELECT {} FROM flow WHERE ({});",
            self.name, self.filter
        );
        let mut stmt = db.prepare(&sql_command)?;

        let record_iter = stmt.query_map([], |row| {
            Ok(StringCategoryRecord {
                value: row.get(0).expect("missing value"),
            })
        })?;
        
        // If the name is ndpi_appid, we skip the "unknown" category
        // because it is not a valid category.
        // This is a special case for ndpi_appid, which is used to
        // filter out the "unknown" category from the histogram.
        if self.name == "ndpi_appid" {
            for record in record_iter {
                let record = record?;
                if record.value != "unknown" {
                    // unknown is not a valid category
                    self.add(&record.value);
                }
            }
        } else {
            for record in record_iter {
                let record = record?;
                self.add(&record.value);
            }
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
        conn.execute_batch(HISTOGRAM_STRING_CATEGORY).unwrap();

        let mut tx = conn.transaction().unwrap();
        tx.set_drop_behavior(DropBehavior::Commit);
        let mut appender: Appender = tx
            .appender("histogram_summary")
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;
        let _ = self.serialize_summary(&mut appender, observe, vlan, proto);
        let mut appender: Appender = tx
            .appender("histogram_string_category")
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
    ) -> StringCategoryHistogram {
        let sql_command = format!(
            "SELECT * FROM histogram_summary WHERE observe='{}' AND vlan = {} AND proto='{}' AND name='{}';",
            observe, vlan, proto, name
        );
        let mut stmt = db.prepare(&sql_command).expect("histogram load");

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

        let map: HashMap<String, i64> = HashMap::new();
        let mut histogram_category = StringCategoryHistogram {
            name: summary.name,
            count: summary.count,
            filter: summary.filter,
            map,
        };

        //
        //
        //
        let sql_command = format!(
            "SELECT * FROM histogram_string_category WHERE observe='{}' AND vlan = {} AND proto='{}' AND name='{}';",
            observe, vlan, proto, name
        );
        let mut stmt = db
            .prepare(&sql_command)
            .expect("histogram_string_category load");

        let historgram_iter = stmt
            .query_map([], |row| {
                Ok(StringHistogramTable {
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
        StringCategory
    }
    pub fn get_probability(&mut self, record: &MemFlowRecord) -> f64 {
        match self.name.as_str() {
            "proto" => self.probability(&record.proto),
            "iflags" => self.probability(&record.iflags),
            "uflags" => self.probability(&record.uflags),
            "scountry" => self.probability(&record.scountry),
            "dcountry" => self.probability(&record.dcountry),
            "spd" => self.probability(&record.spd),
            "ndpi_appid" => self.probability(&record.appid),
            "ndpi_category" => self.probability(&record.category),
            "orient" => self.probability(&record.orient),
            _ => panic!("invalid feature"),
        }
    }
}
