/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::pipeline::use_motherduck;

use crate::utils::duckdb::{duckdb_open, duckdb_open_memory, duckdb_open_readonly};
use chrono::prelude::*;
use chrono::{TimeZone, Utc};
use duckdb::{Appender, Connection, DropBehavior};
use std::fs;
use std::process;
use std::time::SystemTime;

use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::FileType;
use crate::pipeline::Interval;
use std::io::Error;

use crate::model::table::appid::AppIdTable;
use crate::model::table::asn::AsnTable;
use crate::model::table::bytes::BytesTable;
use crate::model::table::country::CountryTable;
use crate::model::table::dns::DnsTable;
use crate::model::table::doh::DohTable;
use crate::model::table::flow::FlowTable;
use crate::model::table::ip::IpTable;
use crate::model::table::packets::PacketsTable;
use crate::model::table::proto::ProtoTable;
use crate::model::table::quic::QuicTable;
use crate::model::table::ssh::SshTable;
use crate::model::table::vlan::VlanTable;
use crate::model::table::vpn::VpnTable;
use crate::model::table::TableTrait;
use crate::model::table::CREATE_METRICS_TABLE;

#[derive(Debug)]
pub struct BucketRecord {
    pub ts: i64,
}

pub struct AggregationProcessor {
    pub command: String,
    pub input: String,
    pub output: String,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
    pub retention: u16,
    pub db_conn: Connection,
    pub cache_directory: String,
    pub cache_file: String,
    pub table_list: Vec<Box<dyn TableTrait>>,
    pub dtg_format: String,
    pub use_motherduck: bool,
}

impl AggregationProcessor {
    pub fn new(
        command: &str,
        input: &str,
        output: &str,
        pass: &str,
        interval_string: &str,
        extension_string: &str,
        options_string: &str,
    ) -> Result<Self, Error> {
        let interval = parse_interval(interval_string);
        let mut options = parse_options(options_string);
        options.entry("retention").or_insert("30");
        options.entry("tables").or_insert("all");
        options.entry("cache").or_insert(output);

        let use_motherduck = use_motherduck(output).expect("motherduck env");
        if use_motherduck {
            println!("{}: [motherduck={}]", command, use_motherduck);
        }

        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}={}]", command, key, value);
            }
        }
        let retention = options
            .get("retention")
            .expect("expected retention")
            .parse::<u16>()
            .unwrap();
        let cache_directory = options
            .get("cache")
            .expect("expected --option cache=<directory>")
            .to_string();

        // For now, load all the ables.  In the future, make it a command line option
        //let table_spec = options.get("tables").expect("expected table");

        let appid: AppIdTable = AppIdTable {
            table_name: "appid",
        };
        let asn: AsnTable = AsnTable { table_name: "asn" };
        let bytes: BytesTable = BytesTable {
            table_name: "bytes",
        };
        let country: CountryTable = CountryTable {
            table_name: "country",
        };
        let dns: DnsTable = DnsTable { table_name: "dns" };
        let doh: DohTable = DohTable { table_name: "doh" };
        let flow: FlowTable = FlowTable { table_name: "flow" };
        let ip: IpTable = IpTable { table_name: "ip" };
        let packets: PacketsTable = PacketsTable {
            table_name: "packets",
        };
        let proto: ProtoTable = ProtoTable {
            table_name: "proto",
        };
        let quic: QuicTable = QuicTable { table_name: "quic" };
        let ssh: SshTable = SshTable { table_name: "ssh" };
        let vlan: VlanTable = VlanTable { table_name: "vlan" };
        let vpn: VpnTable = VpnTable { table_name: "vpn" };

        let current_utc: DateTime<Utc> = Utc::now();
        let dtg_format = current_utc.format("%Y%m%d").to_string();
        let cache_file = format!("{}/cache-{}", cache_directory, dtg_format);

        let mut db_conn: Connection = Connection::open_in_memory().expect("memory");
        if use_motherduck {
            db_conn = duckdb_open(output, 2);
            println!("{}: connection established with {}", command, output);
        } else {
            db_conn = duckdb_open(&cache_file, 2);
            println!("{}: cache [{}]", command, cache_file);
        }

        db_conn
            .execute_batch(CREATE_METRICS_TABLE)
            .expect("execute_batch");

        let mut table_list: Vec<Box<dyn TableTrait>> = Vec::new();
        table_list.push(Box::new(appid));
        table_list.push(Box::new(asn));
        table_list.push(Box::new(bytes));
        table_list.push(Box::new(country));
        table_list.push(Box::new(dns));
        table_list.push(Box::new(doh));
        table_list.push(Box::new(flow));
        table_list.push(Box::new(ip));
        table_list.push(Box::new(packets));
        table_list.push(Box::new(proto));
        table_list.push(Box::new(ssh));
        table_list.push(Box::new(quic));
        table_list.push(Box::new(vlan));
        table_list.push(Box::new(vpn));

        Ok(Self {
            command: command.to_string(),
            input: input.to_string(),
            output: output.to_string(),
            pass: pass.to_string(),
            interval: interval,
            extension: extension_string.to_string(),
            retention,
            table_list,
            db_conn,
            cache_directory,
            cache_file,
            dtg_format: dtg_format,
            use_motherduck: use_motherduck,
        })
    }
}
impl FileProcessor for AggregationProcessor {
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
        return true;
    }
    fn process(&mut self, file_list: &Vec<String>, _schema_type: FileType) -> Result<(), Error> {
        // Use iterator and join for file list formatting
        let parquet_list = file_list
            .iter()
            .map(|file| format!("'{}'", file))
            .collect::<Vec<_>>()
            .join(",");
        let parquet_list = format!("[{}]", parquet_list);

        let mem_source = duckdb_open_memory(2);
        let sql_command = format!(
            "CREATE TABLE memtable AS SELECT * FROM read_parquet({});",
            parquet_list
        );
        mem_source
            .execute_batch(&sql_command)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e)))?;

        if self.use_motherduck {
            mem_source
                .execute_batch(CREATE_METRICS_TABLE)
                .map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                })?;
            let mut cache_appender = mem_source.appender("metrics").map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("DuckDB appender error: {}", e),
                )
            })?;
            for table in &self.table_list {
                table.insert(&mem_source, &mut cache_appender);
            }
            let _ = cache_appender.flush();
            let tmp_parquet = ".gnat_metrics.parquet";
            let sql_copy = format!(
                "COPY metrics TO '{}' (FORMAT parquet, COMPRESSION zstd);",
                tmp_parquet
            );
            mem_source.execute_batch(&sql_copy).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;

            println!("{}: uploading to motherduck...", self.command);
            let sql_export = format!(
                "CREATE TABLE IF NOT EXISTS metrics AS SELECT * FROM read_parquet('{}')",
                tmp_parquet
            );
  
            self.db_conn.execute_batch(&sql_export).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;

            fs::remove_file(tmp_parquet).map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("remove_file error: {}", e),
                )
            })?;
        } else {
            {
                let mut tx = self.db_conn.transaction().map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("DuckDB transaction error: {}", e),
                    )
                })?;
                tx.set_drop_behavior(DropBehavior::Commit);
                let mut cache_appender = tx.appender("metrics").map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("DuckDB appender error: {}", e),
                    )
                })?;
                for table in &self.table_list {
                    table.insert(&mem_source, &mut cache_appender);
                }
                let _ = cache_appender.flush();
                drop(cache_appender);

                tx.commit().map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("DuckDB commit error: {}", e),
                    )
                })?;
            }

            println!("{}: exporting", self.command);
            let sql_command = format!("COPY (SELECT *, year(bucket) AS year, month(bucket) AS month, day(bucket) AS day FROM metrics)
                   TO '{}' 
                   (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 100_000, PARTITION_BY (year, month, day), 
                   OVERWRITE_OR_IGNORE,FILENAME_PATTERN 'gnat-{}-{}.{{i}}');", self.output, self.command, self.dtg_format);

            self.db_conn.execute_batch(&sql_command).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
            })?;

            // get timestamps of the first and last record
            let sql_command = "SELECT bucket FROM metrics ORDER BY bucket ASC LIMIT 1;".to_string();
            let mut stmt = self.db_conn.prepare(&sql_command).map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("DuckDB prepare error: {}", e),
                )
            })?;
            let bucket_time = stmt
                .query_row([], |row| {
                    Ok(BucketRecord {
                        ts: row.get(0).expect("missing bucket"),
                    })
                })
                .map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("DuckDB query_row error: {}", e),
                    )
                })?;
            let first = Utc
                .timestamp_opt(bucket_time.ts / 1_000_000, 0)
                .single()
                .ok_or_else(|| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        "invalid timestamp for first record",
                    )
                })?;

            let sql_command =
                "SELECT bucket FROM metrics ORDER BY bucket DESC LIMIT 1;".to_string();
            let mut stmt = self.db_conn.prepare(&sql_command).map_err(|e| {
                Error::new(
                    std::io::ErrorKind::Other,
                    format!("DuckDB prepare error: {}", e),
                )
            })?;
            let bucket_time = stmt
                .query_row([], |row| {
                    Ok(BucketRecord {
                        ts: row.get(0).expect("missing bucket"),
                    })
                })
                .map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("DuckDB query_row error: {}", e),
                    )
                })?;
            let last = Utc
                .timestamp_opt(bucket_time.ts / 1_000_000, 0)
                .single()
                .ok_or_else(|| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        "invalid timestamp for last record",
                    )
                })?;

            // determine if it's time to clear the db cache
            if first.day() != last.day() {
                let current_utc: DateTime<Utc> = Utc::now();
                let dtg_format = current_utc.format("%Y%m%d").to_string();
                let cache_file = format!("{}/cache-{}", self.cache_directory, dtg_format);

                // only reset when the day has changed
                if dtg_format != self.dtg_format {
                    self.dtg_format = dtg_format;

                    self.db_conn = duckdb_open(&cache_file, 2);
                    self.db_conn
                        .execute_batch(CREATE_METRICS_TABLE)
                        .map_err(|e| {
                            Error::new(std::io::ErrorKind::Other, format!("DuckDB error: {}", e))
                        })?;

                    fs::remove_file(self.cache_file.clone()).map_err(|e| {
                        Error::new(
                            std::io::ErrorKind::Other,
                            format!("remove_file error: {}", e),
                        )
                    })?;
                    self.cache_file = cache_file;

                    println!("{}: reset cache [{}]", self.command, self.cache_file);
                }
            }
        }
        mem_source.close().map_err(|e| {
            Error::new(
                std::io::ErrorKind::Other,
                format!("DuckDB close error: {:?}", e),
            )
        })?;
        Ok(())
    }
}
