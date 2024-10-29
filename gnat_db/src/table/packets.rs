use crate::TableTrait;

use questdb::ingress::{Buffer, TimestampMicros, TimestampNanos};

#[derive(Debug)]
struct PacketsRecord {
    bucket: i64,
    observ: String,
    packets: String,
    count: i64,
}

pub struct PacketsTable {
    pub table_name: &'static str,
}

impl TableTrait for PacketsTable {
    fn table_name(&self) -> &'static str {
        self.table_name
    }
    fn create(&self, api_url: &String) {
        println!("creating table: {} {}", api_url, self.table_name);

        let sql_create_table = format!(
            "CREATE TABLE IF NOT EXISTS {}(
                bucket TIMESTAMP,
                observ SYMBOL CAPACITY 64 INDEX,
                bytes SYMBOL CAPACITY 8192 INDEX,
                count LONG,
                timestamp TIMESTAMP) 
                TIMESTAMP(timestamp) PARTITION BY HOUR;",
                self.table_name
        );

        //
        // Post the request to the QuestDB API
        //
        let url = url::Url::parse_with_params(api_url, &[("query", sql_create_table)])
            .expect("invalid url params");

        match reqwest::blocking::get(url) {
            Ok(r) => println!("verified {} table: {:?}", self.table_name, r.status()),
            Err(e) => panic!("Error: creating {} table - {:?}", self.table_name, e),
        };
    }
    fn insert(&self, sink: &mut questdb::ingress::Sender, source: &duckdb::Connection) {
        //
        // query DuckDB memtable
        //
        let mut stmt = source.prepare("SELECT time_bucket (INTERVAL '1' minute, stime) as bucket,
                                            observ,
                                            sum(packets+rpackets),
                                            count() 
                                        FROM memtable 
                                        GROUP BY all 
                                        ORDER BY all;").unwrap();

        let record_iter = stmt
            .query_map([], |row| {
                Ok(PacketsRecord {
                    bucket: row.get(0).expect("missing bucket"),
                    observ: row.get(1).expect("missing observ"),
                    packets: row.get(2).expect("missing packets"),
                    count: row.get(3).expect("missing count"),
                })
            })
            .unwrap();

        let mut buffer = Buffer::new();
        for r in record_iter {
            let record = r.unwrap();
            let _ = buffer
                .table(self.table_name)
                .unwrap()
                .column_ts("bucket", TimestampMicros::new(record.bucket * 60000000))
                .unwrap()
                .symbol("observ", record.observ)
                .unwrap()
                .symbol("packets", record.packets)
                .unwrap()
                .column_i64("count", record.count)
                .unwrap()
                .at(TimestampNanos::now())
                .unwrap();
            if buffer.len() >= (104857600 - 1048576) {
                sink.flush(&mut buffer).unwrap();
            }
        }
    }
}
