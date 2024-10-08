/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

//use duckdb::arrow::datatypes::ArrowNativeType;
//use questdb::ingress::{Buffer, Sender, TimestampNanos};

use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use duckdb::Connection;
/* 
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
}

fn insert_questdb_records(
    input_spec: &String,
    db_in: &Connection,
    db_out: &mut questdb::ingress::Sender,
) {
    let mut buffer = Buffer::new();

    let sql_command = format!("SELECT * FROM '{}';", input_spec);

    let mut stmt = db_in.prepare(&sql_command).unwrap();

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
            .column_str("iflags", record.iflags)
            .unwrap()
            .column_str("uflags", record.uflags)
            .unwrap()
            .column_i64("tcpseq", record.tcpseq.to_i64().unwrap())
            .unwrap()
            .column_i64("rtcpseq", record.rtcpseq.to_i64().unwrap())
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
            .column_str("mac", record.mac)
            .unwrap()
            .column_str("rmac", record.rmac)
            .unwrap()
            .at(TimestampNanos::new(record.stime * 1000))
            .unwrap();
        db_out.flush(&mut buffer).unwrap();
    }
}

pub fn export_questdb(input_spec: &String, db_in: &Connection, db_out: &String) -> bool {
    match Sender::from_conf(format!("tcp::addr={db_out};")) {
        Ok(mut db_out) => insert_questdb_records(input_spec, db_in, &mut db_out),
        Err(e) => {
            eprintln!("error: processing file: {e:?}");
            return false;
        }
    };
    println!("exported: {} => {}", input_spec, db_out);
    true
}
*/
pub fn export_file(input_spec: &String, output_spec: &String, format: &String) -> bool {
    let conn = match Connection::open_in_memory() {
        Ok(s) => s,
        Err(e) => panic!("error:  open_in_memory() - {}", e),
    };

    let sql_command: String;
    match format.as_str() {
        "csv" => {
            sql_command = format!(
                "COPY (SELECT * FROM '{}') TO '{}.csv' (HEADER, DELIMITER ',');",
                input_spec, output_spec
            );
            println!("exported: {} => {}", input_spec, output_spec);
        }
        "json" => {
            sql_command = format!(
                "COPY (SELECT * FROM '{}') TO '{}';",
                input_spec, output_spec
            );
        }
        _ => {
            // default is JSON
            sql_command = format!(
                "COPY (SELECT * FROM '{}') TO '{}';",
                input_spec, output_spec
            );
            println!("exported: {} => {}", input_spec, output_spec);
        }
    }

    match conn.execute_batch(&sql_command) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: exporting file {} -- {:?}", input_spec, e);
            return false;
        }
    };

    true
}

pub fn export(
    input_spec: &String,
    output_spec: &String,
    processed_spec: &String,
    polling: bool,
    format: &String,
) {
    if PathBuf::from(input_spec.clone()).is_dir() {
        println!("\tinput spec: {}", input_spec);
        println!("\toutput spec: {}", output_spec);
        println!("\tprocessed spec: {}", processed_spec);
        println!("\texport format: {}", format);
        println!("\tpolling: {}", polling);

        let poll_interval = Duration::from_millis(1000);
        println!("export scanner: running [{}]", input_spec);
        loop {
            let mut counter = 0;
            let directory = match fs::read_dir(input_spec) {
                Ok(d) => d,
                Err(e) => panic!("error: reading directory {} -- {:?}", input_spec, e),
            };

            for entry in directory {
                let file = entry.unwrap();
                let file_name = String::from(file.file_name().to_string_lossy());
                let src_path = String::from(file.path().to_string_lossy());

                if let Ok(metadata) = file.metadata() {
                    // don't process zero length files
                    let error_file = format!(
                        "{}/{}.error",
                        processed_spec,
                        file.file_name().to_string_lossy()
                    );
                    if metadata.len() <= 0 {
                        let _ = fs::rename(file.path(), error_file);
                        continue;
                    }
                }

                if !file_name.starts_with(".") && file_name.ends_with(".parquet") {
                    let dst_spec;
                    if format == "questdb" {
                        dst_spec = output_spec.clone();
                    } else {
                        dst_spec = format!("{}/{}.{}", output_spec, file_name, format);
                    }

                    if export_file(&src_path, &dst_spec, format) {
                        if !processed_spec.is_empty() {
                            let processed_path =
                                format!("{}/{}", &processed_spec, file_name.to_string());

                            match fs::rename(src_path.clone(), processed_path.clone()) {
                                Ok(c) => c,
                                Err(e) => panic!(
                                    "error: moving {} -> {}: {:?}",
                                    src_path, processed_path, e
                                ),
                            };
                        }
                    } else {
                        eprintln!("error: exporting {} => {}", src_path, dst_spec);
                        std::process::exit(exitcode::PROTOCOL);
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
        export_file(input_spec, output_spec, format);
    }
}
