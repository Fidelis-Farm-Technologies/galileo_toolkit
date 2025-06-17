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
use crate::model::table::NumberRecord;
use crate::model::table::{FeatureSummaryRecord, HistogramSummaryTable, NumericHistogramTable};
use duckdb::{params, Appender, Connection, DropBehavior};
use std::cmp::min;
use std::collections::HashMap;

#[derive(Debug)]
pub struct NumberHistogram {
    name: String,
    bin_boundary: Vec<i64>,
    bin_frequency: Vec<u64>,
    bin_count: u64,
    count: u64,
}

impl NumberHistogram {
    pub fn new(name: &str, bin_count: u64) -> NumberHistogram {
        if bin_count < 2 {
            panic!("Number of bins must be at least 2");
        }
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
        for i in 0..self.bin_frequency.len() - 1 {
            if value >= self.bin_boundary[i] && value < self.bin_boundary[i + 1] {
                return (self.bin_frequency[i] + 1) as f64 / (self.count as f64 + 1.0);
            }
        }
        1.0 / ((self.count + 1) as f64)
    }

    pub fn build(&mut self, db: &Connection, observe: &String, vlan: i64, proto: &String) {
        let sql_command = format!(
            "SELECT {} FROM flow WHERE observe='{}' AND dvlan = {} AND proto='{}';",
            self.name, observe, vlan, proto
        );
        let mut stmt = db.prepare(&sql_command).expect("build numeric_category");

        let record_iter = stmt
            .query_map([], |row| {
                Ok(NumberRecord {
                    value: row.get(0).expect("missing value"),
                })
            })
            .expect("number map");

        let mut data: Vec<i64> = Vec::new();
        for record in record_iter {
            let record = record.unwrap();
            data.push(record.value);
        }
        self.count = data.len() as u64;
        let binner = IntegerEqualFrequencyBinner::new(data, self.bin_count as usize);
        self.bin_boundary = binner.calculate_boundaries();
        self.bin_frequency = binner.bin_frequency();
        self.bin_count = self.bin_boundary.len() as u64;
        /*
        println!("Bin name: {:?}", self.name);
        println!("Sample count: {:?}", self.count);
        println!("Bin count: {:?}", self.bin_count);
        println!("Bin boundaries: {:?}", self.bin_boundary);
        println!("Bin frequencies: {:?}", self.bin_frequency);
        // Get a detailed report of bins
        //let report = binner.bin_report();
        //println!("Bin report:");
        //for (i, (start, end, count)) in report.iter().enumerate() {
        //    println!("\tBin {} [{}, {}): {} items", i + 1, start, end, count);
        //}
        println!("=================================");
        */
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

/// Equal-frequency binning implementation for integer histograms
pub struct IntegerEqualFrequencyBinner {
    data: Vec<i64>,
    num_bins: usize,
}

impl IntegerEqualFrequencyBinner {
    /// Create a new IntegerEqualFrequencyBinner instance
    pub fn new(data: Vec<i64>, num_bins: usize) -> Self {
        if num_bins < 1 {
            panic!("Number of bins must be at least 1");
        }

        IntegerEqualFrequencyBinner { data, num_bins }
    }

    /// Calculate bin boundaries that will contain approximately equal
    /// number of data points in each bin
    pub fn calculate_boundaries(&self) -> Vec<i64> {
        // Create a copy of the data and sort it
        let mut sorted_data = self.data.clone();
        sorted_data.sort();

        // Create a vector to hold the boundaries
        let mut boundaries = Vec::with_capacity(self.num_bins + 1);

        // Handle empty data case
        if sorted_data.is_empty() {
            return Vec::new();
        }

        // Always include the minimum value as the first boundary
        boundaries.push(*sorted_data.first().unwrap());

        // If we only want one bin, just return min and max+1
        if self.num_bins == 1 {
            boundaries.push(sorted_data.last().unwrap() + 1);
            return boundaries;
        }

        let n = sorted_data.len();

        // Calculate the ideal number of elements per bin
        let items_per_bin = n as f64 / self.num_bins as f64;

        // Calculate boundaries
        for i in 1..self.num_bins {
            // Calculate the ideal index for this boundary
            let idx = (i as f64 * items_per_bin).round() as usize;
            let idx = std::cmp::min(idx, n - 1); // Ensure we don't go out of bounds

            // Get the value at this index
            let value = sorted_data[idx];

            // For integer data, we need to handle duplicates at the boundary carefully
            let mut boundary = value;

            // If there are duplicates at the boundary, we need to decide whether to
            // include all duplicates in the current bin or move them to the next bin

            // Find the range of indices with the same value
            let mut dup_start = idx;
            while dup_start > 0 && sorted_data[dup_start - 1] == value {
                dup_start -= 1;
            }

            let mut dup_end = idx;
            while dup_end < n - 1 && sorted_data[dup_end + 1] == value {
                dup_end += 1;
            }

            // If there are duplicates spanning the boundary, decide which bin they should go in
            if dup_start < idx && dup_end > idx {
                // Calculate the ideal bin boundary position
                let ideal_pos = i as f64 * items_per_bin;

                // Check if most duplicates should go in the current bin or next bin
                let mid_dup = (dup_start + dup_end) as f64 / 2.0;

                if mid_dup > ideal_pos {
                    // More duplicates should go in the next bin
                    // Set boundary to the current value
                    boundary = value;
                } else {
                    // More duplicates should go in the current bin
                    // Find the next different value after the duplicates
                    if dup_end < n - 1 {
                        boundary = sorted_data[dup_end + 1];
                    } else {
                        boundary = value + 1;
                    }
                }
            }

            boundaries.push(boundary);
        }

        // Always include one past the maximum value as the last boundary
        boundaries.push(sorted_data.last().unwrap() + 1);

        // Ensure boundaries are unique and strictly increasing
        let mut unique_boundaries = Vec::new();
        let mut prev_boundary = None;

        for &boundary in &boundaries {
            if prev_boundary.is_none() || Some(boundary) > prev_boundary {
                unique_boundaries.push(boundary);
                prev_boundary = Some(boundary);
            }
        }

        // If we ended up with fewer bins due to merging, we need to adjust
        if unique_boundaries.len() < 2 {
            // Ensure at least one valid bin
            if let Some(&max) = sorted_data.last() {
                if unique_boundaries.is_empty() {
                    unique_boundaries.push(*sorted_data.first().unwrap_or(&0));
                }
                unique_boundaries.push(max + 1);
            }
        }

        unique_boundaries
    }

    /// Get the bin counts - the number of elements in each bin
    pub fn bin_frequency(&self) -> Vec<u64> {
        let boundaries = self.calculate_boundaries();
        let num_bins = boundaries.len() - 1;
        let mut counts = vec![0; num_bins];

        // Count elements in each bin
        for &value in &self.data {
            // Find the bin for this value using binary search
            match boundaries.binary_search(&value) {
                Ok(idx) => {
                    // Value is exactly at a boundary
                    if idx < num_bins {
                        counts[idx] += 1;
                    }
                }
                Err(idx) => {
                    // Value is between boundaries
                    if idx > 0 && idx <= num_bins {
                        counts[idx - 1] += 1;
                    }
                }
            }
        }

        counts
    }

    /// Get a report of the bins and their contents
    pub fn bin_report(&self) -> Vec<(i64, i64, u64)> {
        let boundaries = self.calculate_boundaries();
        let counts = self.bin_frequency();

        let mut report = Vec::new();
        for i in 0..counts.len() {
            report.push((boundaries[i], boundaries[i + 1], counts[i]));
        }

        report
    }
}
