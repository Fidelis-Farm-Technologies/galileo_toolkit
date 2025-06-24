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
use crate::model::table::IpAddrCategoryRecord;
use crate::model::table::{HistogramSummaryTable, IpAddrHistogramTable};

use crate::model::table::MemFlowRecord;
use byteorder::{ByteOrder, LittleEndian};
use duckdb::{params, Appender, Connection, DropBehavior};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug)]
pub struct IpAddrCategoryHistogram {
    name: String,
    hash_size: u64,
    count: usize,
    map: HashMap<u64, u64>,
}

impl IpAddrCategoryHistogram {
    pub fn new(name: &String, hash_size: u64) -> IpAddrCategoryHistogram {
        IpAddrCategoryHistogram {
            name: name.to_string(),
            hash_size,
            count: 0,
            map: HashMap::new(),
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
                "ipaddr_category",
                self.count,
                self.hash_size,
                0,
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
            "HBOS: serializing [{}/{}/{}/{}]...",
            observe, vlan, proto, self.name
        );
        for (hash_bin, value) in &self.map {
            appender
                .append_row(params![observe, vlan, proto, self.name, hash_bin, value])
                .unwrap();
        }
    }
    fn get_key(&mut self, ipaddr: &String) -> u64 {
        let modulus = 65536;
        let mut key: u64 = 0;
        let ip_address = IpAddr::from_str(ipaddr).expect("invalid ip address");

        match ip_address {
            IpAddr::V4(ipv4) => match ipv4.octets()[0] {
                0..=127 => {
                    let mut ip_octets = ipv4.octets();
                    ip_octets[1] = 0;
                    ip_octets[2] = 0;
                    ip_octets[3] = 0;
                    let index: u64 = LittleEndian::read_u32(&ip_octets) as u64;
                    key = index.rem_euclid(modulus);
                }
                128..=191 => {
                    let mut ip_octets = ipv4.octets();
                    ip_octets[2] = 0;
                    ip_octets[3] = 0;
                    let index: u64 = LittleEndian::read_u32(&ip_octets) as u64;
                    key = index.rem_euclid(modulus);
                }
                192..=223 => {
                    let mut ip_octets = ipv4.octets();
                    ip_octets[3] = 0;
                    let index: u64 = LittleEndian::read_u32(&ip_octets) as u64;
                    key = index.rem_euclid(modulus);
                }
                224..=239 => {
                    let mut ip_octets = ipv4.octets();
                    ip_octets[3] = 0;
                    let index: u64 = LittleEndian::read_u32(&ip_octets) as u64;
                    key = index.rem_euclid(modulus);
                }
                240..=255 => {
                    let ip_octets = ipv4.octets();
                    let index: u64 = LittleEndian::read_u32(&ip_octets) as u64;
                    key = index.rem_euclid(modulus);
                    //println!("Class D: {} => {} {}", ipv4, index, key)
                }
            },
            IpAddr::V6(ipv6) => {
                let ip_octets = ipv6.octets();
                let index = LittleEndian::read_u128(&ip_octets);
                key = index.rem_euclid(modulus as u128) as u64;
                //println!("IPv6 address, no class assigned: {}", ip_address);
            }
        }

        key
    }
    fn add(&mut self, ipaddr: &String) {
        let key = self.get_key(ipaddr);
        let value = self.map.entry(key).or_insert(0);
        *value += 1;
        self.count += 1;
    }
    pub fn probability(&mut self, ipaddr: &String) -> f64{        
        let key = self.get_key(ipaddr);
        if let Some(frequency) = self.map.get(&key) {
            return (*frequency + 1) as f64 / (self.count as f64 + 1.0);
        }
        1.0 / (self.count as f64 + 1.0)
    }
    pub fn build(&mut self, db: &Connection, observe: &String, vlan: i64, proto: &String) -> Result<(), duckdb::Error> {
        let sql_command = format!(
            "SELECT {} FROM flow WHERE observe='{}' AND dvlan = {} AND proto='{}';",
            self.name, observe, vlan, proto
        );
        let mut stmt = db.prepare(&sql_command)?;

        let record_iter = stmt
            .query_map([], |row| {
                Ok(IpAddrCategoryRecord {
                    value: row.get(0).expect("missing value"),
                })
            })?;

        for record in record_iter {
            let record = record?;
            self.add(&record.value);
        }
        Ok(())
    }
    pub fn serialize(&self, conn: &mut Connection, observe: &String, vlan: i64, proto: &String) {
        conn.execute_batch(HISTOGRAM_SUMMARY).unwrap();
        conn.execute_batch(HISTOGRAM_IPADDR_CATEGORY).unwrap();

        let mut tx = conn.transaction().unwrap();
        tx.set_drop_behavior(DropBehavior::Commit);
        let mut appender: Appender = tx.appender("histogram_summary").unwrap();
        self.serialize_summary(&mut appender, observe, vlan, proto);
        let mut appender: Appender = tx.appender("histogram_ipaddr_category").unwrap();
        self.serialize_histogram(&mut appender, observe, vlan, proto);
    }
    pub fn load(
        db: &Connection,
        name: &String,
        observe: &String,
        vlan: i64,
        proto: &String,
    ) -> IpAddrCategoryHistogram {
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
                })
            })
            .unwrap();
        //
        //
        //
        let map: HashMap<u64, u64> = HashMap::new();
        let mut histogram_category = IpAddrCategoryHistogram {
            name: summary.name,
            hash_size: summary.hash_size,
            count: summary.count,
            map,
        };

        let sql_command = format!(
            "SELECT * FROM histogram_ipaddr_category WHERE observe='{}' AND vlan = {} AND proto='{}' AND name='{}';",
            observe, vlan, proto, name
        );
        let mut stmt = db
            .prepare(&sql_command)
            .expect("histogram_ipaddr_category load");

        let historgram_iter = stmt
            .query_map([], |row| {
                Ok(IpAddrHistogramTable {
                    observe: row.get(0).expect("missing observe"),
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
        IpNetworkCategory
    }
    pub fn get_probability(&mut self, record: &MemFlowRecord) -> f64 {
        match self.name.as_str() {
            "saddr" => self.probability(&record.saddr),
            "daddr" => self.probability(&record.daddr),
            _ => panic!("invalid feature"),
        }
    }
}
