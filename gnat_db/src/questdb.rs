/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use duckdb::arrow::datatypes::ArrowNativeType;
use questdb::ingress::{Buffer, Sender, TimestampNanos};

use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use chrono::offset::Utc;
use duckdb::Connection;
use url::Url;

#[derive(Debug)]
struct FlowRecord {
    observ: String,
    stime: i64,
    etime: i64,
    dur: u32,
    rtt: u32,
    pcr: f64,
    proto: String,
    addr: String,
    raddr: String,
    port: u16,
    rport: u16,
    iflags: String,
    uflags: String,
    tcpseq: u32,
    rtcpseq: u32,
    vlan: u16,
    rvlan: u16,
    pkts: u64,
    rpkts: u64,
    bytes: u64,
    rbytes: u64,
    entropy: u8,
    rentropy: u8,
    iat: u64,
    riat: u64,
    stdev: u64,
    rstdev: u64,
    tcpurg: u32,
    rtcpurg: u32,
    smallpktcnt: u32,
    rsmallpktcnt: u32,
    largepktcnt: u32,
    rlargepktcnt: u32,
    nonemptypktcnt: u32,
    rnonemptypktcnt: u32,
    firstnonemptysize: u16,
    rfirstnonemptysize: u16,
    maxpktsize: u16,
    rmaxpktsize: u16,
    stdevpayload: u16,
    rstdevpayload: u16,
    spd: String,
    appid: String,
    reason: String,
    mac: String,
    rmac: String,
    country: String,
    rcountry: String,
    asn: u32,
    rasn: u32,
    asnorg: String,
    rasnorg: String,
    model: String,
    score: f64,
}

fn insert_questdb_records(
    input_spec: &String,
    db_in: &Connection,
    db_out: &mut questdb::ingress::Sender,
) {
    let mut buffer = Buffer::new();

    let sql_command = format!("SELECT * FROM '{}';", input_spec);

    let mut stmt = db_in.prepare(&sql_command).unwrap();

    let mut count = 0;
    let start = Instant::now();
    let record_iter = stmt
        .query_map([], |row| {
            Ok(FlowRecord {
                observ: row.get(0).expect("missing observ"),
                stime: row.get(1).expect("missing stime"),
                etime: row.get(2).expect("missing etime"),
                dur: row.get(3).expect("missing dur"),
                rtt: row.get(4).expect("missing rtt"),
                pcr: row.get(5).expect("missing pcr"),
                proto: row.get(6).expect("missing proto"),
                addr: row.get(7).expect("missing addr"),
                raddr: row.get(8).expect("missing radrr"),
                port: row.get(9).expect("missing port"),
                rport: row.get(10).expect("missing rport"),
                iflags: row.get(11).expect("missing iflags"),
                uflags: row.get(12).expect("missing uflags"),
                tcpseq: row.get(13).expect("missig tcpseq"),
                rtcpseq: row.get(14).expect("missing rtcpseq"),
                vlan: row.get(15).expect("missing vlan"),
                rvlan: row.get(16).expect("missing rvlan"),
                pkts: row.get(17).expect("missing pkts"),
                rpkts: row.get(18).expect("missing rpkts"),
                bytes: row.get(19).expect("missing bytes"),
                rbytes: row.get(20).expect("missing rbytes"),
                entropy: row.get(21).expect("missing entropy"),
                rentropy: row.get(22).expect("missing rentropy"),
                iat: row.get(23).expect("missing iat"),
                riat: row.get(24).expect("missing riat"),
                stdev: row.get(25).expect("missing stdev"),
                rstdev: row.get(26).expect("missing rstdev"),
                tcpurg: row.get(27).expect("missing tcpurg"),
                rtcpurg: row.get(28).expect("missgin rtcpurg"),
                smallpktcnt: row.get(29).expect("missing smallpkt"),
                rsmallpktcnt: row.get(30).expect("missing rsmallpktcnt"),
                largepktcnt: row.get(31).expect("missing largepktcnt"),
                rlargepktcnt: row.get(32).expect("missing rlargepktcnt"),
                nonemptypktcnt: row.get(33).expect("missing nonemptypktcnt"),
                rnonemptypktcnt: row.get(34).expect("missing rnonemptypktcnt"),
                firstnonemptysize: row.get(35).expect("missing firstnonemptysize"),
                rfirstnonemptysize: row.get(36).expect("missing rfirstnonemptysize"),
                maxpktsize: row.get(37).expect("missing maxpktsize"),
                rmaxpktsize: row.get(38).expect("missing rmaxpktsize"),
                stdevpayload: row.get(39).expect("missing stdevpayload"),
                rstdevpayload: row.get(40).expect("missing rstdevpayload"),
                spd: row.get(41).expect("missing spd"),
                appid: row.get(42).expect("missing appid"),
                reason: row.get(43).expect("missing reason"),
                mac: row.get(44).expect("missing mac"),
                rmac: row.get(45).expect("missing rmac"),
                country: row.get(46).expect("missing country"),
                rcountry: row.get(47).expect("missing rcountry"),
                asn: row.get(48).expect("missing asn"),
                rasn: row.get(49).expect("missing rasn"),
                asnorg: row.get(50).expect("missing asnorg"),
                rasnorg: row.get(51).expect("missing rasnorg"),
                model: row.get(52).expect("missing model"),                
                score: row.get(53).expect("missing score"),
            })
        })
        .unwrap();

    for r in record_iter {
        let record = r.unwrap();
        let _ = buffer
            .table("flow")
            .unwrap()
            .symbol("observ", record.observ)
            .unwrap()
            .symbol("proto", record.proto)
            .unwrap()
            .symbol("applabel", record.appid)
            .unwrap()
            .symbol("spd", record.spd)
            .unwrap()
            .symbol("reason", record.reason)
            .unwrap()
            .symbol("asnorg", record.asnorg)
            .unwrap()
            .symbol("rasnorg", record.rasnorg)
            .unwrap()
            .symbol("country", record.country)
            .unwrap()
            .symbol("rcountry", record.rcountry)
            .unwrap()
            .symbol("mac", record.mac)
            .unwrap()
            .symbol("rmac", record.rmac)
            .unwrap()
            .symbol("iflags", record.iflags)
            .unwrap()
            .symbol("uflags", record.uflags)
            .unwrap()
            .symbol("model", record.model)
            .unwrap()
            .column_f64("score", record.score)
            .unwrap()
            .column_ts("stime", TimestampNanos::new(record.stime * 1000))
            .unwrap()
            .column_ts("etime", TimestampNanos::new(record.etime * 1000))
            .unwrap()
            .column_i64("dur", record.dur.to_i64().unwrap())
            .unwrap()
            .column_i64("rtt", record.rtt.to_i64().unwrap())
            .unwrap()
            .column_f64("pcr", record.pcr)
            .unwrap()
            .column_i64("vlan", record.vlan.to_i64().unwrap())
            .unwrap()
            .column_i64("rvlan", record.rvlan.to_i64().unwrap())
            .unwrap()
            .column_str("addr", record.addr)
            .unwrap()
            .column_str("raddr", record.raddr)
            .unwrap()
            .column_i64("port", record.port.to_i64().unwrap())
            .unwrap()
            .column_i64("rport", record.rport.to_i64().unwrap())
            .unwrap()
            .column_i64("asn", record.asn.to_i64().unwrap())
            .unwrap()
            .column_i64("rasn", record.rasn.to_i64().unwrap())
            .unwrap()
            .column_i64("tcpseq", record.tcpseq.to_i64().unwrap_or(0))
            .unwrap()
            .column_i64("rtcpseq", record.rtcpseq.to_i64().unwrap_or(0))
            .unwrap()
            .column_i64("vlan", record.vlan.to_i64().unwrap())
            .unwrap()
            .column_i64("rvlan", record.rvlan.to_i64().unwrap())
            .unwrap()
            .column_i64("pkts", record.pkts.to_i64().unwrap())
            .unwrap()
            .column_i64("rpkts", record.rpkts.to_i64().unwrap())
            .unwrap()
            .column_i64("bytes", record.bytes.to_i64().unwrap())
            .unwrap()
            .column_i64("rbytes", record.rbytes.to_i64().unwrap())
            .unwrap()
            .column_i64("entropy", record.entropy.to_i64().unwrap())
            .unwrap()
            .column_i64("rentropy", record.rentropy.to_i64().unwrap())
            .unwrap()
            .column_i64("iat", record.iat.to_i64().unwrap())
            .unwrap()
            .column_i64("riat", record.riat.to_i64().unwrap())
            .unwrap()
            .column_i64("stdev", record.stdev.to_i64().unwrap())
            .unwrap()
            .column_i64("rstdev", record.rstdev.to_i64().unwrap())
            .unwrap()
            .column_i64("tcpurg", record.tcpurg.to_i64().unwrap())
            .unwrap()
            .column_i64("rtcpurg", record.rtcpurg.to_i64().unwrap())
            .unwrap()
            .column_i64("smallpktcnt", record.smallpktcnt.to_i64().unwrap())
            .unwrap()
            .column_i64("rsmallpktcnt", record.rsmallpktcnt.to_i64().unwrap())
            .unwrap()
            .column_i64("largepktcnt", record.largepktcnt.to_i64().unwrap())
            .unwrap()
            .column_i64("rlargepktcnt", record.rlargepktcnt.to_i64().unwrap())
            .unwrap()
            .column_i64("nonemptypktcnt", record.nonemptypktcnt.to_i64().unwrap())
            .unwrap()
            .column_i64("rnonemptypktcnt", record.rnonemptypktcnt.to_i64().unwrap())
            .unwrap()
            .column_i64(
                "firstnonemptysize",
                record.firstnonemptysize.to_i64().unwrap(),
            )
            .unwrap()
            .column_i64(
                "rfirstnonemptysize",
                record.rfirstnonemptysize.to_i64().unwrap(),
            )
            .unwrap()
            .column_i64("maxpktsize", record.maxpktsize.to_i64().unwrap())
            .unwrap()
            .column_i64("rmaxpktsize", record.rmaxpktsize.to_i64().unwrap())
            .unwrap()
            .column_i64("stdevpayload", record.stdevpayload.to_i64().unwrap())
            .unwrap()
            .column_i64("rstdevpayload", record.rstdevpayload.to_i64().unwrap())
            .unwrap()
            .at(TimestampNanos::new(record.stime * 1000))
            .unwrap();

        count += 1;
        if buffer.len() >= (104857600 - 1048576) {
            db_out.flush(&mut buffer).unwrap();
        }
    }

    db_out.flush(&mut buffer).unwrap();

    let duration = start.elapsed();
    let records_per_sec: f64 = count as f64 / duration.as_millis() as f64;

    println!(
        "Exported: {}, count: {}, duration: {} ms, rate:  {} per/sec",
        input_spec,
        count,
        duration.as_millis(),
        (records_per_sec * 1000.0).round()
    );
}

pub fn insert_questdb_table(input_spec: &String, host_spec: &String, ilp_port: u16) {
    let db_in = match Connection::open_in_memory() {
        Ok(s) => s,
        Err(e) => panic!("Error: open_in_memory() - {}", e),
    };

    match Sender::from_conf(format!("tcp::addr={}:{};", host_spec, ilp_port)) {
        Ok(mut db_out) => insert_questdb_records(input_spec, &db_in, &mut db_out),
        Err(e) => panic!("Error: processing file: {e:?}"),
    };
}

pub fn create_questdb_table(host_spec: &String, api_port: u16) {
    let sql_create_table: &'static str = r#"
        CREATE TABLE IF NOT EXISTS flow(
            observ SYMBOL CAPACITY 64 INDEX,
            proto SYMBOL CAPACITY 1024 INDEX,
            applabel SYMBOL CAPACITY 8192 INDEX,
            spd SYMBOL CAPACITY 8192 INDEX,
            reason SYMBOL CAPACITY 8 INDEX,
            asnorg SYMBOL CAPACITY 4096 INDEX,
            rasnorg SYMBOL CAPACITY 4096 INDEX,
            country SYMBOL CAPACITY 256 INDEX,
            rcountry SYMBOL CAPACITY 256 INDEX,
            mac SYMBOL CAPACITY 65536 INDEX,
            rmac SYMBOL CAPACITY 65536 INDEX,
            iflags SYMBOL CAPACITY 65536 INDEX,
            uflags SYMBOL CAPACITY 65536 INDEX,
            model SYMBOL CAPACITY 64 INDEX,
            score FLOAT,
            stime TIMESTAMP,
            etime TIMESTAMP,
            dur INT,
            rtt INT,
            pcr FLOAT,
            vlan INT,
            rvlan INT,
            addr VARCHAR,
            raddr VARCHAR,
            port INT,
            rport INT,
            asn INT,
            rasn INT,
            tcpseq LONG,
            rtcpseq LONG,
            pkts LONG,
            rpkts LONG,
            bytes LONG,
            rbytes LONG,
            entropy SHORT,
            rentropy SHORT,
            iat LONG,
            riat LONG,
            stdev LONG,
            rstdev LONG,
            tcpurg INT,
            rtcpurg INT,
            smallpktcnt INT,
            rsmallpktcnt INT,
            largepktcnt INT,
            rlargepktcnt INT,
            nonemptypktcnt INT,
            rnonemptypktcnt INT,
            firstnonemptysize SHORT,
            rfirstnonemptysize SHORT,
            maxpktsize SHORT,
            rmaxpktsize SHORT,
            stdevpayload SHORT,
            rstdevpayload SHORT,
            timestamp TIMESTAMP
            ) TIMESTAMP(timestamp) PARTITION BY HOUR;"#;

    let host = format!("http://{}:{}/exec", host_spec, api_port);
    let url =
        Url::parse_with_params(&host, &[("query", sql_create_table)]).expect("invalid url params");

    match reqwest::blocking::get(url) {
        Ok(r) => println!("verified flow table: {}", r.status()),
        Err(e) => panic!("Error: creating flow table - {:?}", e),
    };
}

pub fn drop_questdb_partitions(host_spec: &String, api_port: u16, retention_days: u16) {
    let sql_drop_partition = format!(
        "ALTER TABLE flow DROP PARTITION WHERE timestamp < dateadd('d', -{}, now());",
        retention_days
    );
    let mut host = format!("http://{}:{}/exec", host_spec, api_port);
    let drop_url =
        Url::parse_with_params(&host, &[("query", sql_drop_partition)]).expect("invalid url");

    match reqwest::blocking::get(drop_url) {
        Ok(_r) => println!("dropped days older than {}", retention_days),
        Err(_e) => panic!("Error: dropping day partition(s)"),
    };

    host = format!("http://{}:{}/exec", host_spec, api_port);
    let vacuum_url =
        Url::parse_with_params(&host, &[("query", "VACUUM TABLE flow;")]).expect("invalid url");
    match reqwest::blocking::get(vacuum_url) {
        Ok(_r) => println!("vacuumed flow table"),
        Err(_e) => panic!("Error: vacumming flow table)"),
    };
}

pub fn questdb_export(
    input_spec: &String,
    host_spec: &String,
    ilp_port: u16,
    api_port: u16,
    processed_spec: &String,
    retention_days: u16,
    polling: bool,
) {
    if PathBuf::from(input_spec.clone()).is_dir() {
        println!("\tinput spec: {}", input_spec);
        println!("\tprocessed spec: {}", processed_spec);
        println!("\tdb spec: {}", host_spec);
        println!("\tilp port: {}", ilp_port);
        println!("\tapi port: {}", api_port);
        println!("\tpolling: {}", polling);

        //
        // create flow table if it does not exist
        //
        create_questdb_table(host_spec, api_port);

        let mut last = Utc::now();

        let poll_interval = Duration::from_millis(1000);
        println!("export scanner: running [{}]", input_spec);
        loop {
            //
            // is it time to drop older days (partitions)?
            //
            let now = Utc::now();
            let duration = now.signed_duration_since(last);
            if duration.num_days() > 1 {
                last = now;
                drop_questdb_partitions(host_spec, api_port, retention_days);
            }

            let directory = match fs::read_dir(input_spec) {
                Ok(d) => d,
                Err(e) => panic!("Error: reading directory {} -- {:?}", input_spec, e),
            };
            let mut counter = 0;
            for entry in directory {
                let file = entry.unwrap();
                let file_name = String::from(file.file_name().to_string_lossy());
                let src_path = String::from(file.path().to_string_lossy());

                if let Ok(metadata) = file.metadata() {
                    if metadata.len() <= 0 {
                        // skip file
                        continue;
                    }
                }

                if file_name.starts_with("galileo") && file_name.ends_with(".parquet") {

                    insert_questdb_table(&src_path, &host_spec, ilp_port);
                    
                    if !processed_spec.is_empty() {
                        let processed_path =
                            format!("{}/{}", &processed_spec, file_name.to_string());

                        match fs::rename(src_path.clone(), processed_path.clone()) {
                            Ok(c) => c,
                            Err(e) => {
                                panic!("Error: moving {} -> {}: {:?}", src_path, processed_path, e)
                            }
                        };
                    }

                    counter += 1;
                }
            }
            if !polling {
                break;
            }
            if counter == 0 {
                thread::sleep(poll_interval);
            }
        }
    } else {
        insert_questdb_table(input_spec, &host_spec, ilp_port);
    }
}
