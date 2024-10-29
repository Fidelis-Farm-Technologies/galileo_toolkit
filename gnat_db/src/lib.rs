pub mod table {
    pub mod appid;
    pub mod asn;
    pub mod bytes;
    pub mod country;
    pub mod dns;
    pub mod doh;    
    pub mod flow;
    pub mod packets;
    pub mod proto;
    pub mod ssh;     
    pub mod quic;    
}

pub trait TableTrait {
    fn table_name(&self) -> &'static str;
    fn create(&self, api_url: &String);
    fn insert(&self, sink: &mut questdb::ingress::Sender, source: &duckdb::Connection);

    fn drop(&self, api_url: &String, retention_days: u16) {
        println!("dropping partition table: {} {:?}", api_url, self.table_name());
        let sql_drop_partition = format!(
            "ALTER TABLE {:?} DROP PARTITION WHERE timestamp < dateadd('d', -{}, now());", self.table_name(),
            retention_days
        );
        let drop_url =
            url::Url::parse_with_params(api_url, &[("query", sql_drop_partition)]).expect("invalid url");

        println!("Executing: {}", drop_url.as_str());
        match reqwest::blocking::get(drop_url) {
            Ok(_r) => println!("dropped appid partitions days older than {}", retention_days),
            Err(_e) => panic!("Error: dropping flow partition(s)"),
        };

        let sql_vacuum_table = format!("VACUUM TABLE {:?};", self.table_name());
        let vacuum_url =
            url::Url::parse_with_params(api_url, &[("query", sql_vacuum_table)]).expect("invalid url");

        println!("Executing: {}", vacuum_url.as_str());
        match reqwest::blocking::get(vacuum_url) {
            Ok(_r) => println!("vacuumed flow table"),
            Err(_e) => panic!("Error: vacumming flow table)"),
        };
    }
}
