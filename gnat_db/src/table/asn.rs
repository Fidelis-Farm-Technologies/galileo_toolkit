use crate::TableTrait;

use questdb::ingress::{Buffer, TimestampMicros, TimestampNanos};

#[derive(Debug)]
struct AsnRecord {
    bucket: i64,
    observ: String,
    dasn: i64,
    dasnorg: String,
    count: i64,
}

pub struct AsnTable {
    pub table_name: &'static str,
}

impl TableTrait for AsnTable {
    fn table_name(&self) -> &'static str {
        self.table_name
    }
    fn create(&self, api_url: &String) {
        let sql_create_table = format!(
            "CREATE TABLE IF NOT EXISTS {}(
                bucket TIMESTAMP,
                observ SYMBOL CAPACITY 64 INDEX,
                dasnorg SYMBOL CAPACITY 8192 INDEX,                
                dasn long,
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
            Ok(r) => println!("Database importer: verified [{}] table: {:?}", self.table_name, r.status()),
            Err(e) => panic!("Error: creating {} table - {:?}", self.table_name, e),
        };
    }
    fn insert(&self, sink: &mut questdb::ingress::Sender, source: &duckdb::Connection) {
        //
        // query DuckDB memtable
        //
        let mut stmt = source
            .prepare(
                "SELECT time_bucket (INTERVAL '1' minute, stime) as bucket,
                                            observ,
                                            dasn,                                            
                                            dasnorg,                                            
                                            count() 
                                        FROM memtable 
                                        GROUP BY all 
                                        ORDER BY all;",
            )
            .unwrap();

        let record_iter = stmt
            .query_map([], |row| {
                Ok(AsnRecord {
                    bucket: row.get(0).expect("missing bucket"),
                    observ: row.get(1).expect("missing observ"),
                    dasn: row.get(2).expect("missing dasn"),
                    dasnorg: row.get(3).expect("missing dasnorg"),
                    count: row.get(4).expect("missing count"),
                })
            })
            .unwrap();
        let mut count = 0;
        let mut buffer = Buffer::new();
        for r in record_iter {
            let record = r.unwrap();
            let _ = buffer
                .table(self.table_name)
                .unwrap()
                .symbol("observ", record.observ)
                .unwrap()
                .symbol("dasnorg", record.dasnorg)
                .unwrap()
                .column_i64("dasn", record.dasn)
                .unwrap()
                .column_ts("bucket", TimestampMicros::new(record.bucket))
                .unwrap()
                .column_i64("count", record.count)
                .unwrap()
                .at(TimestampNanos::now())
                .unwrap();
            if buffer.len() >= (104857600 - 1048576) {
                sink.flush(&mut buffer).unwrap();
            }
            count += 1;
        }
        if count > 0 {
            sink.flush(&mut buffer).unwrap();
            println!("Table [{}]: {} new records", self.table_name, count);
        }
    }
}
