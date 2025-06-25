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
use crate::model::table::HistogramIntegerValue;
use crate::model::table::MemFlowRecord;
use crate::model::table::NumberRecord;
use crate::model::table::{FeatureSummaryRecord, HistogramSummaryTable, NumericHistogramTable};
use duckdb::{params, Appender, Connection, DropBehavior};
use std::cmp::min;
use std::collections::HashMap;
use std::error::Error;

#[derive(Debug)]
pub struct NumberHistogram {
    name: String,
    bin_boundary: Vec<i64>,
    bin_frequency: Vec<usize>,
    bin_count: usize,
    count: usize,
}

impl NumberHistogram {
    pub fn new(name: &str, bin_count: usize) -> NumberHistogram {
        NumberHistogram {
            name: name.to_string(),
            bin_boundary: Vec::new(),
            bin_frequency: Vec::new(),
            bin_count: bin_count,
            count: 0,
        }
    }

    fn serialize_summary(
        &self,
        appender: &mut Appender,
        observe: &String,
        vlan: i64,
        proto: &String,
    ) {
        appender
            .append_row(params![
                observe,
                vlan,
                proto,
                self.name,
                "numerical",
                self.count,
                0,
                self.bin_count,
            ])
            .unwrap();
    }
    fn serialize_histogram(
        &self,
        appender: &mut Appender,
        observe: &String,
        vlan: i64,
        proto: &String,
    ) {
        println!(
            "{}: serializing [{}/{}/{}/{}]...",
            self.name, observe, vlan, proto, self.name
        );

        let mut bin_num = 0;
        for boundary in self.bin_boundary.iter() {
            appender
                .append_row(params![observe, vlan, proto, self.name, bin_num, boundary])
                .unwrap();
            bin_num += 1;
        }
    }

    pub fn probability(&self, value: i64) -> f64 {
        for i in 0..self.bin_boundary.len() - 1 {
            if value <= self.bin_boundary[i] {
                return (self.bin_frequency[i] + 1) as f64 / (self.count as f64 + 1.0);
            }
        }
        1.0 / ((self.count + 1) as f64)
    }

    pub fn build(
        &mut self,
        db: &Connection,
        observe: &String,
        vlan: i64,
        proto: &String,
    ) -> Result<(), duckdb::Error> {
        let sql_create_command = format!(
            "CREATE OR REPLACE TABLE number AS SELECT {} 
            FROM flow WHERE observe='{}' AND dvlan = {} AND proto='{}';",
            self.name, observe, vlan, proto,
        );
        db.execute_batch(&sql_create_command)?;

        let sql_command = format!("FROM histogram_values(number,{});", self.name);
        let mut stmt = db.prepare(&sql_command)?;

        let record_iter = stmt
            .query_map([], |row| {
                Ok(HistogramIntegerValue {
                    boundary: row.get(0).expect("missing value"),
                    frequency: row.get(1).expect("missing value"),
                })
            })
            .unwrap();

        for record in record_iter {
            let record = record.expect("error reading record");
            self.bin_boundary.push(record.boundary);
            self.bin_frequency.push(record.frequency);
            self.count += record.frequency;
            self.bin_count += 1;
        }

        Ok(())
    }
    pub fn serialize(&self, conn: &mut Connection, observe: &String, vlan: i64, proto: &String) {
        conn.execute_batch(HISTOGRAM_SUMMARY).unwrap();
        conn.execute_batch(HISTOGRAM_NUMERICAL).unwrap();

        let mut tx = conn.transaction().unwrap();
        tx.set_drop_behavior(DropBehavior::Commit);
        let mut appender: Appender = tx.appender("histogram_summary").unwrap();
        self.serialize_summary(&mut appender, observe, vlan, proto);
        let mut appender: Appender = tx.appender("histogram_numerical").unwrap();
        self.serialize_histogram(&mut appender, observe, vlan, proto);
    }
    pub fn load(
        db: &Connection,
        name: &String,
        observe: &String,
        vlan: i64,
        proto: &String,
    ) -> NumberHistogram {
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
                })
            })
            .unwrap();
        //
        //
        //

        let mut histogram_numerical = NumberHistogram {
            name: summary.name,
            bin_boundary: vec![0; summary.bin_count as usize],
            bin_frequency: vec![0; summary.bin_count as usize],
            bin_count: summary.bin_count,
            count: summary.count,
        };

        //
        //
        //
        let sql_command = format!(
            "SELECT * FROM histogram_numerical WHERE observe='{}' AND vlan = {} AND proto='{}' AND name='{}';",
            observe, vlan, proto, name
        );
        let mut stmt = db.prepare(&sql_command).expect("build histogram_numeric");

        let historgram_iter = stmt
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

        for histogram in historgram_iter {
            let record = histogram.unwrap();
            histogram_numerical.bin_boundary[record.key as usize] = record.value;
        }

        histogram_numerical
    }
    pub fn name(self) -> String {
        self.name
    }
    pub fn histogram_type(self) -> HistogramType {
        Numerical
    }
    pub fn get_probability(&mut self, record: &MemFlowRecord) -> f64 {
        match self.name.as_str() {
            "dur" => self.probability(record.dur as i64),
            "rtt" => self.probability(record.rtt as i64),
            "pcr" => self.probability(record.pcr as i64),
            "sbytes" => self.probability(record.sbytes as i64),
            "dbytes" => self.probability(record.dbytes as i64),
            "spkts" => self.probability(record.spkts as i64),
            "dpkts" => self.probability(record.dpkts as i64),
            "sentropy" => self.probability(record.sentropy as i64),
            "dentropy" => self.probability(record.dentropy as i64),
            "siat" => self.probability(record.siat as i64),
            "diat" => self.probability(record.diat as i64),
            "ssmallpktcnt" => self.probability(record.ssmallpktcnt as i64),
            "dsmallpktcnt" => self.probability(record.dsmallpktcnt as i64),
            "slargepktcnt" => self.probability(record.slargepktcnt as i64),
            "dlargepktcnt" => self.probability(record.dlargepktcnt as i64),
            "sfirstnonemptycnt" => self.probability(record.sfirstnonemptycnt as i64),
            "dfirstnonemptycnt" => self.probability(record.dfirstnonemptycnt as i64),
            "smaxpktsize" => self.probability(record.smaxpktsize as i64),
            "dmaxpktsize" => self.probability(record.dmaxpktsize as i64),
            "sstdevpayload" => self.probability(record.sstdevpayload as i64),
            "dstdevpayload" => self.probability(record.dstdevpayload as i64),
            _ => panic!("invalid feature"),
        }
    }
}
