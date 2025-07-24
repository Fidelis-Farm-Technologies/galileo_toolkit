/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use duckdb::{params, Connection, Error};

use crate::model::histogram::ipaddr_category::IpAddrCategoryHistogram;
use crate::model::histogram::number::NumberHistogram;
use crate::model::histogram::numeric_category::NumericCategoryHistogram;
use crate::model::histogram::string_category::StringCategoryHistogram;
use crate::model::histogram::time_category::TimeCategoryHistogram;

use crate::model::histogram::{
    DEFAULT_ASN_MODULUS, DEFAULT_FREQUENCY_BIN_SIZE, DEFAULT_NETWORK_MODULUS, DEFAULT_PORT_MODULUS,
    DEFAULT_VLAN_MODULUS, HBOS_SCORE, HBOS_SUMMARY, NO_MODULUS,
};
use crate::model::table::DistinctObserveRecord;

use crate::model::table::HbosSummaryRecord;
use crate::model::table::MemFlowRecord;
use crate::utils::duckdb::duckdb_open;

use chrono::Datelike;
use chrono::{DateTime, Utc};
use duckdb::{Appender, DropBehavior};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

enum Severity {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Severe = 4,
    Critical = 5,
    Emergency = 6,
}

pub struct HistogramModels {
    pub observe: String,
    pub vlan: i64,
    pub proto: String,
    pub numerical: HashMap<String, NumberHistogram>,
    pub numeric_category: HashMap<String, NumericCategoryHistogram>,
    pub string_category: HashMap<String, StringCategoryHistogram>,
    pub ipaddr_category: HashMap<String, IpAddrCategoryHistogram>,
    pub time_category: HashMap<String, TimeCategoryHistogram>,
    pub low: f64,
    pub medium: f64,
    pub high: f64,
    pub severe: f64,
    pub filter: String,
}

impl HistogramModels {
    pub fn serialize(&self, conn: &mut Connection) -> Result<(), Error> {
        for (_name, histogram) in &self.numerical {
            let _ = histogram.serialize(conn, &self.observe, self.vlan, &self.proto);
        }

        for (_name, histogram) in &self.numeric_category {
            let _ = histogram.serialize(conn, &self.observe, self.vlan, &self.proto);
        }

        for (_name, histogram) in &self.string_category {
            let _ = histogram.serialize(conn, &self.observe, self.vlan, &self.proto);
        }

        for (_name, histogram) in &self.ipaddr_category {
            let _ = histogram.serialize(conn, &self.observe, self.vlan, &self.proto);
        }

        for (_name, histogram) in &self.time_category {
            let _ = histogram.serialize(conn, &self.observe, self.vlan, &self.proto);
        }
        Ok(())
    }

    pub fn deserialize(&mut self, conn: &Connection) -> Result<(), Error> {
        let sql_distinct_command = format!(
            "SELECT DISTINCT observe,vlan,proto,name,histogram FROM histogram_summary 
            WHERE observe='{}' AND vlan = {} AND proto='{}' GROUP BY ALL ORDER BY ALL;",
            self.observe, self.vlan, self.proto
        );

        let mut stmt = conn.prepare(&sql_distinct_command).expect("sql prepare");
        let record_iter = stmt
            .query_map([], |row| {
                Ok(DistinctObserveRecord {
                    observe: row.get(0).expect("missing value"),
                    vlan: row.get(1).expect("missing value"),
                    proto: row.get(2).expect("missing value"),
                    name: row.get(3).expect("missing value"),
                    histogram: row.get(4).expect("missing value"),
                })
            })
            .expect("query map");

        for record in record_iter {
            let record = record.unwrap();
            match record.histogram.as_str() {
                "numerical" => {
                    let histogram = NumberHistogram::load(
                        conn,
                        &record.name,
                        &record.observe,
                        record.vlan,
                        &record.proto,
                    );
                    self.numerical.insert(record.name, histogram);
                }
                "numeric_category" => {
                    let histogram = NumericCategoryHistogram::load(
                        conn,
                        &record.name,
                        &record.observe,
                        record.vlan,
                        &record.proto,
                    );
                    self.numeric_category.insert(record.name, histogram);
                }
                "string_category" => {
                    let histogram = StringCategoryHistogram::load(
                        conn,
                        &record.name,
                        &record.observe,
                        record.vlan,
                        &record.proto,
                    );
                    self.string_category.insert(record.name, histogram);
                }
                "ipaddr_category" => {
                    let histogram = IpAddrCategoryHistogram::load(
                        conn,
                        &record.name,
                        &record.observe,
                        record.vlan,
                        &record.proto,
                    );
                    self.ipaddr_category.insert(record.name, histogram);
                }
                "time_category" => {
                    let histogram = TimeCategoryHistogram::load(
                        conn,
                        &record.name,
                        &record.observe,
                        record.vlan,
                        &record.proto,
                    );
                    self.time_category.insert(record.name, histogram);
                }
                _ => panic!("invalid histogram type"),
            }
        }

        let sql_command = format!(
            "SELECT * FROM hbos_summary WHERE observe='{}' AND vlan = {} AND proto='{}';",
            self.observe, self.vlan, self.proto
        );
        let mut stmt = conn.prepare(&sql_command).expect("hbos_summary load");
        let hbos_summary = stmt
            .query_row([], |row| {
                Ok(HbosSummaryRecord {
                    observe: row.get(0).expect("missing observe"),
                    vlan: row.get(1).expect("missing vlan"),
                    proto: row.get(2).expect("missing proto"),
                    min: row.get(3).expect("missing min"),
                    max: row.get(4).expect("missing max"),
                    skewness: row.get(5).expect("missing skewness"),
                    avg: row.get(6).expect("missing avg"),
                    std: row.get(7).expect("missing std"),
                    mad: row.get(8).expect("missing mad"),
                    median: row.get(9).expect("missing median"),
                    quantile: row.get(10).expect("missing quantile"),
                    low: row.get(11).expect("missing low"),
                    medium: row.get(12).expect("missing med"),
                    high: row.get(13).expect("missing high"),
                    severe: row.get(14).expect("missing severe"),
                    filter: row.get(15).expect("missing filter"),
                })
            })
            .expect("HbosSummaryRecord");

        self.filter = hbos_summary.filter;
        self.low = hbos_summary.low;
        self.medium = hbos_summary.medium;
        self.high = hbos_summary.high;
        self.severe = hbos_summary.severe;
        Ok(())
    }

    pub fn generate_trigger_data(
        &mut self,
        db_in: &mut Connection,
        db_out: &mut Connection,
    ) -> Result<u64, Error> {
        let sql_command = format!(
            "SELECT * EXCLUDE(tag, hbos_map, ndpi_risk_list) 
             FROM flow 
             WHERE observe='{}' AND dvlan = {} AND proto='{}' AND trigger > 0;",
            self.observe, self.vlan, self.proto
        );
        let mut stmt = db_in.prepare(&sql_command).expect("sql trigger");

        let record_iter = stmt
            .query_map([], |row| {
                Ok(MemFlowRecord {
                    stream: row.get(0).expect("missing value"),
                    id: row.get(1).expect("missing value"),
                    observe: row.get(2).expect("missing value"),
                    stime: row.get(3).expect("missing value"),
                    etime: row.get(4).expect("missing value"),
                    dur: row.get(5).expect("missing value"),
                    rtt: row.get(6).expect("missing value"),
                    pcr: row.get(7).expect("missing value"),
                    proto: row.get(8).expect("missing value"),
                    saddr: row.get(9).expect("missing value"),
                    daddr: row.get(10).expect("missing value"),
                    sport: row.get(11).expect("missing value"),
                    dport: row.get(12).expect("missing value"),
                    iflags: row.get(13).expect("missing value"),
                    uflags: row.get(14).expect("missing value"),
                    stcpseq: row.get(15).expect("missing value"),
                    dtcpseq: row.get(16).expect("missing value"),
                    svlan: row.get(17).expect("missing value"),
                    dvlan: row.get(18).expect("missing value"),
                    spkts: row.get(19).expect("missing value"),
                    dpkts: row.get(20).expect("missing value"),
                    sbytes: row.get(21).expect("missing value"),
                    dbytes: row.get(22).expect("missing value"),
                    sentropy: row.get(23).expect("missing value"),
                    dentropy: row.get(24).expect("missing value"),
                    siat: row.get(25).expect("missing value"),
                    diat: row.get(26).expect("missing value"),
                    sstdev: row.get(27).expect("missing value"),
                    dstdev: row.get(28).expect("missing value"),
                    dtcpurg: row.get(29).expect("missing value"),
                    stcpurg: row.get(30).expect("missing value"),
                    ssmallpktcnt: row.get(31).expect("missing value"),
                    dsmallpktcnt: row.get(32).expect("missing value"),
                    slargepktcnt: row.get(33).expect("missing value"),
                    dlargepktcnt: row.get(34).expect("missing value"),
                    snonemptypktcnt: row.get(35).expect("missing value"),
                    dnonemptypktcnt: row.get(36).expect("missing value"),
                    sfirstnonemptycnt: row.get(37).expect("missing value"),
                    dfirstnonemptycnt: row.get(38).expect("missing value"),
                    smaxpktsize: row.get(39).expect("missing value"),
                    dmaxpktsize: row.get(40).expect("missing value"),
                    sstdevpayload: row.get(41).expect("missing value"),
                    dstdevpayload: row.get(42).expect("missing value"),
                    spd: row.get(43).expect("missing value"),
                    reason: row.get(44).expect("missing value"),
                    smac: row.get(45).expect("missing value"),
                    dmac: row.get(46).expect("missing value"),
                    scountry: row.get(47).expect("missing value"),
                    dcountry: row.get(48).expect("missing value"),
                    sasn: row.get(49).expect("missing value"),
                    dasn: row.get(50).expect("missing value"),
                    sasnorg: row.get(51).expect("missing value"),
                    dasnorg: row.get(52).expect("missing value"),
                    orient: row.get(53).expect("missing value"),
                    hbos_score: row.get(54).expect("missing value"),
                    hbos_severity: row.get(55).expect("missing value"),
                    appid: row.get(56).expect("missing value"),
                    category: row.get(57).unwrap_or("".to_string()),
                    risk_bits: row.get(58).expect("missing value"),
                    risk_score: row.get(59).expect("missing value"),
                    risk_severity: row.get(60).expect("missing value"),
                    trigger: row.get(61).expect("missing value"),
                })
            })
            .expect("query map failed");

        let mut trigger_count: u64 = 0;
        {
            let _ = db_out.execute_batch("BEGIN TRANSACTION;");

            for record in record_iter {
                let record = record?;

                let mut is_first = true;
                let risk_bits: u64 = record.risk_bits;
                let mut risk_list = format!("list_value(");
                if risk_bits > 0 {
                    for i in 0..64 {
                        let bit_is_set = (risk_bits >> i) & 1 == 1;
                        if bit_is_set {
                            if is_first {
                                is_first = false;
                            } else {
                                risk_list.push_str(",");
                            }
                            risk_list.push_str("'");
                            risk_list.push_str(Self::riskname_by_index(i));
                            risk_list.push_str("'");
                        }
                    }
                }
                risk_list.push_str(")");

                //
                // write hbos map
                //
                let mut hbos_map = format!("map_from_entries([");
                let mut is_first_map = true;

                for (name, histogram) in &mut self.numerical {
                    let feature_prob = histogram.get_probability(&record);
                    if is_first_map {
                        is_first_map = false;
                    } else {
                        hbos_map.push_str(",");
                    }
                    hbos_map.push_str(&format!("{{k:'{}',v:{:.3}}}", name, feature_prob));
                }

                for (name, histogram) in &mut self.numeric_category {
                    let feature_prob = histogram.get_probability(&record);
                    if is_first_map {
                        is_first_map = false;
                    } else {
                        hbos_map.push_str(",");
                    }
                    hbos_map.push_str(&format!("{{k:'{}',v:{:.3}}}", name, feature_prob));
                }

                for (name, histogram) in &mut self.string_category {
                    let feature_prob = histogram.get_probability(&record);
                    if is_first_map {
                        is_first_map = false;
                    } else {
                        hbos_map.push_str(",");
                    }
                    hbos_map.push_str(&format!("{{k:'{}',v:{:.3}}}", name, feature_prob));
                }

                for (name, histogram) in &mut self.ipaddr_category {
                    let feature_prob = histogram.get_probability(&record);
                    if is_first_map {
                        is_first_map = false;
                    } else {
                        hbos_map.push_str(",");
                    }
                    hbos_map.push_str(&format!("{{k:'{}',v:{:.3}}}", name, feature_prob));
                }

                for (name, histogram) in &mut self.time_category {
                    let feature_prob = histogram.get_probability(&record);
                    if is_first_map {
                        is_first_map = false;
                    } else {
                        hbos_map.push_str(",");
                    }
                    hbos_map.push_str(&format!("{{k:'{}',v:{:.3}}}", name, feature_prob));
                }
                hbos_map.push_str("])");

                let sql_insert_command = format!(
                    "INSERT INTO trigger_table BY POSITION VALUES ('{}', {}, {}, {});",
                    record.id, record.trigger, risk_list, hbos_map
                );
                let _ = db_out.execute_batch(&sql_insert_command);
                trigger_count += 1;
            }
            let _ = db_out.execute_batch("COMMIT;");
        }
        Ok(trigger_count)
    }

    pub fn score(&mut self, db_in: &mut Connection, db_out: &mut Connection) -> Result<u64, Error> {
        db_out
            .execute_batch("CREATE OR REPLACE TABLE score_table (id UUID, hbos_score DOUBLE);")?;

        let mut score_appender = db_out.appender("score_table")?;

        let sql_command = format!(
            "SELECT * EXCLUDE(tag, hbos_map, ndpi_risk_list) FROM flow WHERE observe='{}' AND dvlan = {} AND proto='{}' AND {};", 
            self.observe, self.vlan, self.proto, self.filter
        );
        let mut stmt = db_in.prepare(&sql_command)?;
        let record_iter = stmt.query_map([], |row| {
            Ok(MemFlowRecord {
                stream: row.get(0).expect("missing value"),
                id: row.get(1).expect("missing value"),
                observe: row.get(2).expect("missing value"),
                stime: row.get(3).expect("missing value"),
                etime: row.get(4).expect("missing value"),
                dur: row.get(5).expect("missing value"),
                rtt: row.get(6).expect("missing value"),
                pcr: row.get(7).expect("missing value"),
                proto: row.get(8).expect("missing value"),
                saddr: row.get(9).expect("missing value"),
                daddr: row.get(10).expect("missing value"),
                sport: row.get(11).expect("missing value"),
                dport: row.get(12).expect("missing value"),
                iflags: row.get(13).expect("missing value"),
                uflags: row.get(14).expect("missing value"),
                stcpseq: row.get(15).expect("missing value"),
                dtcpseq: row.get(16).expect("missing value"),
                svlan: row.get(17).expect("missing value"),
                dvlan: row.get(18).expect("missing value"),
                spkts: row.get(19).expect("missing value"),
                dpkts: row.get(20).expect("missing value"),
                sbytes: row.get(21).expect("missing value"),
                dbytes: row.get(22).expect("missing value"),
                sentropy: row.get(23).expect("missing value"),
                dentropy: row.get(24).expect("missing value"),
                siat: row.get(25).expect("missing value"),
                diat: row.get(26).expect("missing value"),
                sstdev: row.get(27).expect("missing value"),
                dstdev: row.get(28).expect("missing value"),
                dtcpurg: row.get(29).expect("missing value"),
                stcpurg: row.get(30).expect("missing value"),
                ssmallpktcnt: row.get(31).expect("missing value"),
                dsmallpktcnt: row.get(32).expect("missing value"),
                slargepktcnt: row.get(33).expect("missing value"),
                dlargepktcnt: row.get(34).expect("missing value"),
                snonemptypktcnt: row.get(35).expect("missing value"),
                dnonemptypktcnt: row.get(36).expect("missing value"),
                sfirstnonemptycnt: row.get(37).expect("missing value"),
                dfirstnonemptycnt: row.get(38).expect("missing value"),
                smaxpktsize: row.get(39).expect("missing value"),
                dmaxpktsize: row.get(40).expect("missing value"),
                sstdevpayload: row.get(41).expect("missing value"),
                dstdevpayload: row.get(42).expect("missing value"),
                spd: row.get(43).expect("missing value"),
                reason: row.get(44).expect("missing value"),
                smac: row.get(45).expect("missing value"),
                dmac: row.get(46).expect("missing value"),
                scountry: row.get(47).expect("missing value"),
                dcountry: row.get(48).expect("missing value"),
                sasn: row.get(49).expect("missing value"),
                dasn: row.get(50).expect("missing value"),
                sasnorg: row.get(51).expect("missing value"),
                dasnorg: row.get(52).expect("missing value"),
                orient: row.get(53).expect("missing value"),
                hbos_score: row.get(54).expect("missing value"),
                hbos_severity: row.get(55).expect("missing value"),
                appid: row.get(56).expect("missing value"),
                category: row.get(57).unwrap_or("".to_string()),
                risk_bits: row.get(58).expect("missing value"),
                risk_score: row.get(59).expect("missing value"),
                risk_severity: row.get(60).expect("missing value"),
                trigger: row.get(61).expect("missing value"),
            })
        })?;

        let mut count: u64 = 0;
        for record in record_iter {
            let mut flow_record = record?;
            let mut histogram_map: HashMap<String, f64> = HashMap::new();
            flow_record.hbos_score = 0.0;

            let mut hbos_score: f64 = 0.0;
            for (name, histogram) in &mut self.numerical {
                let feature_prob = histogram.get_probability(&flow_record);
                histogram_map.insert(name.to_string(), feature_prob);
                hbos_score += (1.0 / feature_prob).log10();
            }
            for (name, histogram) in &mut self.numeric_category {
                let feature_prob = histogram.get_probability(&flow_record);
                histogram_map.insert(name.to_string(), feature_prob);
                hbos_score += (1.0 / feature_prob).log10();
            }
            for (name, histogram) in &mut self.string_category {
                let feature_prob = histogram.get_probability(&flow_record);
                histogram_map.insert(name.to_string(), feature_prob);
                hbos_score += (1.0 / feature_prob).log10();
            }
            for (name, histogram) in &mut self.ipaddr_category {
                let feature_prob = histogram.get_probability(&flow_record);
                histogram_map.insert(name.to_string(), feature_prob);
                hbos_score += (1.0 / feature_prob).log10();
            }
            for (name, histogram) in &mut self.time_category {
                let feature_prob = histogram.get_probability(&flow_record);
                histogram_map.insert(name.to_string(), feature_prob);
                hbos_score += (1.0 / feature_prob).log10();
            }
            flow_record.hbos_score = hbos_score;

            flow_record.hbos_severity = if hbos_score > self.severe {
                Severity::Severe as u8
            } else if hbos_score > self.high {
                Severity::High as u8
            } else if hbos_score > self.medium {
                Severity::Medium as u8
            } else if hbos_score > self.low {
                Severity::Low as u8
            } else {
                Severity::None as u8
            };

            count += 1;

            score_appender.append_row(params![flow_record.id, flow_record.hbos_score])?;
        }
        score_appender.flush()?;
        drop(score_appender);
        Ok(count)
    }

    fn get_histogram_severity_levels(&self, db_conn: &mut Connection) -> (f64, f64, f64, f64) {
        //
        // generate histogram of HBOS scores
        //
        {
            let mut stmt = db_conn
                .prepare("FROM histogram(hbos_score, score);")
                .expect("sql prepare");
            let hist_iter = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0).expect("missing bin"),   // bin
                        row.get::<_, f64>(1).expect("missing boundary"), // boundary
                        row.get::<_, String>(2).expect("missing bar"),   // bar
                    ))
                })
                .expect("expected query map");
            for result in hist_iter {
                let (bin, boundary, bar) = result.expect("expected histogram");
                println!(
                    "[{}/{}/{}]\t[{} ({})]: {}",
                    self.observe, self.vlan, self.proto, bin, boundary, bar
                );
            }
        }

        let mut low = 0.0;
        let mut medium = 0.0;
        let mut high = 0.0;
        let mut severe = 0.0;
        let mut max = 0.0;
        {
            let mut stmt = db_conn
                .prepare("FROM histogram_values(hbos_score, score);")
                .expect("sql prepare");
            let hist_iter = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, f64>(0).expect("missing boundary"), // boundary
                        row.get::<_, usize>(1).expect("missing frequency"), // frequency
                    ))
                })
                .expect("expected query map");
            for result in hist_iter {
                let (boundary, _frequency) = result.expect("expected histogram");
                low = medium;
                medium = high;
                high = severe;
                severe = max;
                max = boundary;
            }
        }

        (low, medium, high, severe)
    }
    pub fn summarize(
        &mut self,
        parquet_list: &str,
        sink_conn: &mut Connection,
    ) -> Result<(), Error> {
        // load the parquet files into a temporary duckdb database
        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();

        let db_input_file = format!("summarize.{}.tmp", rfc3339_name.replace(":", "-"));
        let mut db_input = duckdb_open(&db_input_file, 1);

        let sql_command = format!(
            "CREATE OR REPLACE TABLE flow AS (SELECT * FROM read_parquet({}) 
             WHERE observe='{}' AND dvlan = {} AND proto='{}');",
            parquet_list, self.observe, self.vlan, self.proto
        );
        let mut stmt = db_input.execute_batch(&sql_command).expect("sql summarize");

        let sql_command = format!(
            "SELECT * EXCLUDE(id,tag,hbos_map,ndpi_risk_list) FROM flow 
             WHERE {};",
            self.filter
        );

        //println!("\tSQL:{}", sql_command);
        let mut stmt = db_input.prepare(&sql_command).expect("sql summarize");

        println!("\tloading...");
        let record_iter = stmt.query_map([], |row| {
            Ok(MemFlowRecord {
                stream: row.get(0).expect("missing value"),
                id: "".to_string(), // id is not used in this context
                observe: row.get(1).expect("missing value"),
                stime: row.get(2).expect("missing value"),
                etime: row.get(3).expect("missing value"),
                dur: row.get(4).expect("missing value"),
                rtt: row.get(5).expect("missing value"),
                pcr: row.get(6).expect("missing value"),
                proto: row.get(7).expect("missing value"),
                saddr: row.get(8).expect("missing value"),
                daddr: row.get(9).expect("missing value"),
                sport: row.get(10).expect("missing value"),
                dport: row.get(11).expect("missing value"),
                iflags: row.get(12).expect("missing value"),
                uflags: row.get(13).expect("missing value"),
                stcpseq: row.get(14).expect("missing value"),
                dtcpseq: row.get(15).expect("missing value"),
                svlan: row.get(16).expect("missing value"),
                dvlan: row.get(17).expect("missing value"),
                spkts: row.get(18).expect("missing value"),
                dpkts: row.get(19).expect("missing value"),
                sbytes: row.get(20).expect("missing value"),
                dbytes: row.get(21).expect("missing value"),
                sentropy: row.get(22).expect("missing value"),
                dentropy: row.get(23).expect("missing value"),
                siat: row.get(24).expect("missing value"),
                diat: row.get(25).expect("missing value"),
                sstdev: row.get(26).expect("missing value"),
                dstdev: row.get(27).expect("missing value"),
                dtcpurg: row.get(28).expect("missing value"),
                stcpurg: row.get(29).expect("missing value"),
                ssmallpktcnt: row.get(30).expect("missing value"),
                dsmallpktcnt: row.get(31).expect("missing value"),
                slargepktcnt: row.get(32).expect("missing value"),
                dlargepktcnt: row.get(33).expect("missing value"),
                snonemptypktcnt: row.get(34).expect("missing value"),
                dnonemptypktcnt: row.get(35).expect("missing value"),
                sfirstnonemptycnt: row.get(36).expect("missing value"),
                dfirstnonemptycnt: row.get(37).expect("missing value"),
                smaxpktsize: row.get(38).expect("missing value"),
                dmaxpktsize: row.get(39).expect("missing value"),
                sstdevpayload: row.get(40).expect("missing value"),
                dstdevpayload: row.get(41).expect("missing value"),
                spd: row.get(42).expect("missing value"),
                reason: row.get(43).expect("missing value"),
                smac: row.get(44).expect("missing value"),
                dmac: row.get(45).expect("missing value"),
                scountry: row.get(46).expect("missing value"),
                dcountry: row.get(47).expect("missing value"),
                sasn: row.get(48).expect("missing value"),
                dasn: row.get(49).expect("missing value"),
                sasnorg: row.get(50).expect("missing value"),
                dasnorg: row.get(51).expect("missing value"),
                orient: row.get(52).expect("missing value"),
                hbos_score: row.get(53).expect("missing value"),
                hbos_severity: row.get(54).expect("missing value"),
                appid: row.get(55).expect("missing value"),
                category: row.get(56).unwrap_or("".to_string()),
                risk_bits: row.get(57).expect("missing value"),
                risk_score: row.get(58).expect("missing value"),
                risk_severity: row.get(59).expect("missing value"),
                trigger: row.get(60).expect("missing value"),
            })
        })?;

        println!("\tscoring...");
        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        let score_input_file = format!("score.{}.tmp", rfc3339_name.replace(":", "-"));
        let mut score_conn = duckdb_open(&score_input_file, 1);
        {
            score_conn.execute_batch(HBOS_SCORE)?;

            let mut appender: Appender = score_conn.appender("hbos_score")?;

            for record in record_iter {
                let flow_record = record?;

                let mut hbos_score: f64 = 0.0;
                for (_name, histogram) in &mut self.numerical {
                    let feature_prob = histogram.get_probability(&flow_record);
                    hbos_score += (1.0 / feature_prob).log10();
                }

                for (_name, histogram) in &mut self.numeric_category {
                    let feature_prob = histogram.get_probability(&flow_record);
                    hbos_score += (1.0 / feature_prob).log10();
                }

                for (_name, histogram) in &mut self.string_category {
                    let feature_prob = histogram.get_probability(&flow_record);
                    hbos_score += (1.0 / feature_prob).log10();
                }

                for (_name, histogram) in &mut self.ipaddr_category {
                    let feature_prob = histogram.get_probability(&flow_record);
                    hbos_score += (1.0 / feature_prob).log10();
                }

                for (_name, histogram) in &mut self.time_category {
                    let feature_prob = histogram.get_probability(&flow_record);
                    hbos_score += (1.0 / feature_prob).log10();
                }
                appender.append_row(params![hbos_score])?;
            }
            let _ = appender.flush();
            drop(appender);
        }

        //
        // generate histogram summary
        //
        println!("\tsummarizing...");
        let (low, medium, high, severe) = self.get_histogram_severity_levels(&mut score_conn);
        let mut stmt = score_conn.prepare(
            "SELECT min(score),max(score),skewness(score),avg(score),stddev_pop(score),
                     mad(score),median(score),quantile_cont(score, 0.99999) FROM hbos_score;",
        )?;
        let hbos_summary = stmt.query_row([], |row| {
            Ok(HbosSummaryRecord {
                observe: self.observe.clone(),
                vlan: self.vlan,
                proto: self.proto.clone(),
                min: row.get(0).expect("missing min"),
                max: row.get(1).expect("missing max"),
                skewness: row.get(2).expect("missing skew"),
                avg: row.get(3).expect("missing avg"),
                std: row.get(4).expect("missing std"),
                mad: row.get(5).expect("missing mad"),
                median: row.get(6).expect("missing median"),
                quantile: row.get::<_, f64>(7).expect("missing quantile").round(),
                low: low,
                medium: medium,
                high: high,
                severe: severe,
                filter: self.filter.to_string(),
            })
        })?;

        let _ = db_input.close();
        if Path::new(&db_input_file).exists() {
            fs::remove_file(&db_input_file).expect("failed to remove db_input_file");
        }

        let _ = score_conn.close();
        if Path::new(&score_input_file).exists() {
            fs::remove_file(&score_input_file).expect("failed to remove score_input_file");
        }

        println!(
            "[{}/{}/{}] [{}<low,{}<medium,{}<high,{}<severe]",
            hbos_summary.observe,
            hbos_summary.vlan,
            hbos_summary.proto,
            hbos_summary.low,
            hbos_summary.medium,
            hbos_summary.high,
            hbos_summary.severe
        );

        let _ = sink_conn.execute_batch(HBOS_SUMMARY)?;

        let mut appender: Appender = sink_conn.appender("hbos_summary")?;
        appender.append_row(params![
            hbos_summary.observe,
            hbos_summary.vlan,
            hbos_summary.proto,
            hbos_summary.min,
            hbos_summary.max,
            hbos_summary.skewness,
            hbos_summary.avg,
            hbos_summary.std,
            hbos_summary.mad,
            hbos_summary.median,
            hbos_summary.quantile,
            hbos_summary.low,
            hbos_summary.medium,
            hbos_summary.high,
            hbos_summary.severe,
            hbos_summary.filter
        ])?;
        let _ = appender.flush();
        drop(appender);

        Ok(())
    }

    pub fn build(
        &mut self,
        parquet_list: &str,
        feature_list: &Vec<String>,
        filter: &str,
    ) -> Result<(), duckdb::Error> {
        self.filter = filter.to_string();

        // load the parquet files into a temporary duckdb database
        let current_utc: DateTime<Utc> = Utc::now();
        let rfc3339_name: String = current_utc.to_rfc3339();
        let db_input_file = format!("build.{}.tmp", rfc3339_name.replace(":", "-"));

        let mut conn = duckdb_open(&db_input_file, 1);
        let sql_command = format!(
            "CREATE OR REPLACE TABLE flow AS (SELECT * FROM read_parquet({}) 
             WHERE observe='{}' AND dvlan = {} AND proto='{}');",
            parquet_list, self.observe, self.vlan, self.proto
        );
        let mut stmt = conn.execute_batch(&sql_command)?;

        for feature in feature_list {
            match feature.as_str() {
                "stime" => {
                    let mut histogram = TimeCategoryHistogram::new(feature, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.time_category.insert(feature.to_string(), histogram);
                }
                "dur" => {
                    let mut histogram = NumberHistogram::new(
                        &feature.to_string(),
                        DEFAULT_FREQUENCY_BIN_SIZE,
                        &filter,
                    );
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "rtt" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "pcr" => {
                    let mut histogram =
                        NumericCategoryHistogram::new(&(*feature).to_string(), NO_MODULUS, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numeric_category.insert(feature.to_string(), histogram);
                }
                "proto" => {
                    let mut histogram = StringCategoryHistogram::new(feature, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.string_category.insert(feature.to_string(), histogram);
                }
                "saddr" => {
                    let mut histogram = IpAddrCategoryHistogram::new(
                        &(*feature).to_string(),
                        DEFAULT_NETWORK_MODULUS,
                        &filter,
                    );
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.ipaddr_category.insert(feature.to_string(), histogram);
                }
                "daddr" => {
                    let mut histogram = IpAddrCategoryHistogram::new(
                        &(*feature).to_string(),
                        DEFAULT_NETWORK_MODULUS,
                        &filter,
                    );
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.ipaddr_category.insert(feature.to_string(), histogram);
                }
                "dport" => {
                    let mut histogram = NumericCategoryHistogram::new(
                        &(*feature).to_string(),
                        DEFAULT_PORT_MODULUS,
                        &filter,
                    );
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numeric_category.insert(feature.to_string(), histogram);
                }
                "sport" => {
                    let mut histogram = NumericCategoryHistogram::new(
                        &(*feature).to_string(),
                        DEFAULT_PORT_MODULUS,
                        &filter,
                    );
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numeric_category.insert(feature.to_string(), histogram);
                }
                "iflags" => {
                    let mut histogram = StringCategoryHistogram::new(feature, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.string_category.insert(feature.to_string(), histogram);
                }
                "uflags" => {
                    let mut histogram = StringCategoryHistogram::new(feature, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.string_category.insert(feature.to_string(), histogram);
                }
                "dvlan" => {
                    let mut histogram = NumericCategoryHistogram::new(
                        &(*feature).to_string(),
                        DEFAULT_VLAN_MODULUS,
                        &filter,
                    );
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numeric_category.insert(feature.to_string(), histogram);
                }
                "sbytes" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "dbytes" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "spkts" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "dpkts" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "sentropy" => {
                    let mut histogram =
                        NumericCategoryHistogram::new(&(*feature).to_string(), NO_MODULUS, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numeric_category.insert(feature.to_string(), histogram);
                }
                "dentropy" => {
                    let mut histogram =
                        NumericCategoryHistogram::new(&(*feature).to_string(), NO_MODULUS, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numeric_category.insert(feature.to_string(), histogram);
                }
                "siat" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "diat" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "ssmallpktcnt" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "dsmallpktcnt" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "slargepktcnt" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "dlargepktcnt" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "sfirstnonemptycnt" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "dfirstnonemptycnt" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "smaxpktsize" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "dmaxpktsize" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "sstdevpayload" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "dstdevpayload" => {
                    let mut histogram =
                        NumberHistogram::new(feature, DEFAULT_FREQUENCY_BIN_SIZE, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numerical.insert(feature.to_string(), histogram);
                }
                "sasn" => {
                    let mut histogram =
                        NumericCategoryHistogram::new(feature, DEFAULT_ASN_MODULUS, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numeric_category.insert(feature.to_string(), histogram);
                }
                "dasn" => {
                    let mut histogram =
                        NumericCategoryHistogram::new(feature, DEFAULT_ASN_MODULUS, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.numeric_category.insert(feature.to_string(), histogram);
                }
                "scountry" => {
                    let mut histogram = StringCategoryHistogram::new(feature, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.string_category.insert(feature.to_string(), histogram);
                }
                "dcountry" => {
                    let mut histogram = StringCategoryHistogram::new(feature, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.string_category.insert(feature.to_string(), histogram);
                }
                "spd" => {
                    let mut histogram = StringCategoryHistogram::new(feature, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.string_category.insert(feature.to_string(), histogram);
                }
                "ndpi_appid" => {
                    let mut histogram = StringCategoryHistogram::new(feature, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.string_category.insert(feature.to_string(), histogram);
                }
                "orient" => {
                    let mut histogram = StringCategoryHistogram::new(feature, &filter);
                    histogram.build(&conn, &self.observe, self.vlan, &self.proto)?;
                    self.string_category.insert(feature.to_string(), histogram);
                }
                _ => panic!("invalid feature"),
            }
        }

        let _ = conn.close();
        // remove the temporary database file
        if Path::new(&db_input_file).exists() {
            fs::remove_file(&db_input_file).expect("failed to remove db_input_file");
        }

        Ok(())
    }

    //
    // taken https://github.com/ntop/nDPI/blob/dev/src/include/ndpi_typedefs.h
    //
    const NDPI_RISK_SHORTNAMES: [&str; 57] = [
        "none",                     // NDPI_NO_RISK
        "possible xss",             // NDPI_URL_POSSIBLE_XSS
        "possible sql injection",   // NDPI_URL_POSSIBLE_SQL_INJECTION
        "possible rce injection",   // NDPI_URL_POSSIBLE_RCE_INJECTION
        "binary transfer",          // NDPI_BINARY_APPLICATION_TRANSFER
        "non standard port",        // NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT
        "tls selfsigned cert",      // NDPI_TLS_SELFSIGNED_CERTIFICATE
        "tls obsolete ver",         // NDPI_TLS_OBSOLETE_VERSION
        "tls weak cipher",          // NDPI_TLS_WEAK_CIPHER
        "tls cert expired",         // NDPI_TLS_CERTIFICATE_EXPIRED
        "tls cert mismatch",        // NDPI_TLS_CERTIFICATE_MISMATCH
        "suspicous user agent",     // NDPI_HTTP_SUSPICIOUS_USER_AGENT
        "numeric ip host",          // NDPI_NUMERIC_IP_HOST
        "http suspicious url",      // NDPI_HTTP_SUSPICIOUS_URL
        "http suspicious header",   // NDPI_HTTP_SUSPICIOUS_HEADER
        "tls not https",            // NDPI_TLS_NOT_CARRYING_HTTPS
        "suspicious dga",           // NDPI_SUSPICIOUS_DGA_DOMAIN
        "malformed pkt",            // NDPI_MALFORMED_PACKET
        "ssh obsolete client",      // NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER
        "ssh obsolete server",      // NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER
        "smb insecure ver",         // NDPI_SMB_INSECURE_VERSION
        "free21",                   // NDPI_FREE_21
        "unsafe_proto",             // NDPI_UNSAFE_PROTOCOL
        "dns_susp",                 // NDPI_DNS_SUSPICIOUS_TRAFFIC
        "tls_no_sni",               // NDPI_TLS_MISSING_SNI
        "http suspicous content",   // NDPI_HTTP_SUSPICIOUS_CONTENT
        "risky asn",                // NDPI_RISKY_ASN
        "risky domain",             // NDPI_RISKY_DOMAIN
        "malicious fingerprint",    // NDPI_MALICIOUS_FINGERPRINT
        "malicious cert",           // NDPI_MALICIOUS_SHA1_CERTIFICATE
        "desktop sharing",          // NDPI_DESKTOP_OR_FILE_SHARING_SESSION
        "tls uncommon alpn",        // NDPI_TLS_UNCOMMON_ALPN
        "tls cert too long",        // NDPI_TLS_CERT_VALIDITY_TOO_LONG
        "tls susp ext",             // NDPI_TLS_SUSPICIOUS_EXTENSION
        "tls_fatal error",          // NDPI_TLS_FATAL_ALERT
        "suspicous entropy",        // NDPI_SUSPICIOUS_ENTROPY
        "clear_credential",         // NDPI_CLEAR_TEXT_CREDENTIALS
        "dns large pkt",            // NDPI_DNS_LARGE_PACKET
        "dns_ ragmented",           // NDPI_DNS_FRAGMENTED
        "invalid characters",       // NDPI_INVALID_CHARACTERS
        "possible exploit",         // NDPI_POSSIBLE_EXPLOIT
        "tls cert about to_expire", // NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE
        "punycode",                 // NDPI_PUNYCODE_IDN
        "error code",               // NDPI_ERROR_CODE_DETECTED
        "crawler bot",              // NDPI_HTTP_CRAWLER_BOT
        "anonymous subscriber",     // NDPI_ANONYMOUS_SUBSCRIBER
        "unidirectional",           // NDPI_UNIDIRECTIONAL_TRAFFIC
        "htt obsolete server",      // NDPI_HTTP_OBSOLETE_SERVER
        "periodic flow",            // NDPI_PERIODIC_FLOW
        "minor issues",             // NDPI_MINOR_ISSUES
        "tcp issues",               // NDPI_TCP_ISSUES
        "free51",                   // NDPI_FREE_51
        "tls alpn mismatch",        // NDPI_TLS_ALPN_SNI_MISMATCH
        "malware host",             // NDPI_MALWARE_HOST_CONTACTED
        "binary data transfer",     // NDPI_BINARY_DATA_TRANSFER
        "probing",                  // NDPI_PROBING_ATTEMPT
        "obfuscated",               // NDPI_OBFUSCATED_TRAFFIC
    ];

    pub fn riskname_by_index(index: usize) -> &'static str {
        if index < Self::NDPI_RISK_SHORTNAMES.len() {
            Self::NDPI_RISK_SHORTNAMES[index]
        } else {
            "unknown"
        }
    }
}
