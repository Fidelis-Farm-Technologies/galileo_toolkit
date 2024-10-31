pub mod table {
    pub mod appid;
    pub mod asn;
    pub mod bytes;
    pub mod country;
    pub mod dns;
    pub mod doh;
    pub mod flow;
    pub mod ip;    
    pub mod packets;
    pub mod proto;
    pub mod quic;
    pub mod ssh;
}

pub trait TableTrait {
    fn table_name(&self) -> &'static str;
    fn create(&self, api_url: &String);
    fn insert(&self, sink: &mut questdb::ingress::Sender, source: &duckdb::Connection);

    fn drop(&self, api_url: &String, retention_days: u16) {
        let sql_drop_partition = format!(
            "ALTER TABLE {:?} DROP PARTITION WHERE timestamp < dateadd('d', -{}, now());",
            self.table_name(),
            retention_days
        );
        let drop_url = url::Url::parse_with_params(api_url, &[("query", sql_drop_partition)])
            .expect("invalid url");

    
        match reqwest::blocking::get(drop_url) {
            Ok(_r) => println!(
                "Database importer: dropped partition table [{:?}]",
                self.table_name()
            ),
            Err(_e) => panic!("Error: dropping {:?} partition(s)", self.table_name()),
        };

        let sql_vacuum_table = format!("VACUUM TABLE {:?};", self.table_name());
        let vacuum_url = url::Url::parse_with_params(api_url, &[("query", sql_vacuum_table)])
            .expect("invalid url");

        match reqwest::blocking::get(vacuum_url) {
            Ok(_r) => println!(
                "Database importer: vacuumed table [{:?}]",
                self.table_name()
            ),
            Err(_e) => panic!("Error: vacumming table)"),
        };
    }
}
