use crate::model::table::MetricRecord;
use crate::model::table::TableTrait;
use crate::pipeline::StreamType;
use chrono::{TimeZone, Utc};
use duckdb::{params, Appender};

pub struct BytesTable {
    pub table_name: &'static str,
}

impl TableTrait for BytesTable {
    fn table_name(&self) -> &'static str {
        self.table_name
    }

    fn insert(&self, source: &duckdb::Connection, sink: &mut Appender) {
        //
        // query DuckDB memtable
        //

        let mut stmt = source
            .prepare(
                "SELECT time_bucket (INTERVAL '1' minute, stime) as bucket,observe,sum(sbytes)
                                                            FROM memtable 
                                                            GROUP BY all 
                                                            ORDER BY all;",
            )
            .unwrap();

        let record_iter = stmt
            .query_map([], |row| {
                Ok(MetricRecord {
                    stream: StreamType::TELEMETRY as u32,
                    bucket: row.get(0).expect("missing bucket"),
                    observe: row.get(1).expect("missing observ"),
                    name: "bytes".to_string(),
                    key: "sbytes".to_string(),
                    value: row.get(2).expect("missing count"),
                })
            })
            .unwrap();

        let mut count = 0;
        for r in record_iter {
            let record = r.unwrap();

            let ts = Utc
                .timestamp_opt((record.bucket / 1_000_000) as i64, 0)
                .unwrap();
            sink.append_row(params![
                record.stream,
                ts.to_rfc3339(),
                record.observe,
                record.name,
                record.key,
                record.value
            ])
            .unwrap();
            count += 1;
        }
        if count > 0 {
            println!("\t[{}:{}]", self.table_name, count);
        }

        let mut stmt = source
            .prepare(
                "SELECT time_bucket (INTERVAL '1' minute, stime) as bucket,observe,sum(dbytes)
        FROM memtable 
        GROUP BY all 
        ORDER BY all;",
            )
            .unwrap();

        let record_iter = stmt
            .query_map([], |row| {
                Ok(MetricRecord {
                    stream: StreamType::TELEMETRY as u32,
                    bucket: row.get(0).expect("missing bucket"),
                    observe: row.get(1).expect("missing observ"),
                    name: "bytes".to_string(),
                    key: "dbytes".to_string(),
                    value: row.get(2).expect("missing count"),
                })
            })
            .unwrap();

        let mut count = 0;
        for r in record_iter {
            let record = r.unwrap();

            let ts = Utc
                .timestamp_opt((record.bucket / 1_000_000) as i64, 0)
                .unwrap();
            sink.append_row(params![
                record.stream,
                ts.to_rfc3339(),
                record.observe,
                record.name,
                record.key,
                record.value
            ])
            .unwrap();
            count += 1;
        }
        if count > 0 {
            println!("\t[{}:{}]", self.table_name, count);
        }
    }
}
