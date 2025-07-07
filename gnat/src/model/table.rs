use duckdb::Appender;

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
pub mod vlan;
pub mod vpn;

//use duckdb::types::Value;

#[derive(Debug)]
pub struct FeatureSummaryRecord {
    pub name: String,
    pub min: f64,
    pub max: f64,
    pub skewness: f64,
    pub avg: f64,
    pub std: f64,
    pub mad: f64,
    pub median: f64,
    pub count: u64,
}

#[derive(Debug)]
pub struct HbosBin {
    pub bin: usize,
    pub count: usize,
}

#[derive(Debug)]
pub struct HbosHistogram {
    pub observe: String,
    pub vlan: i64,
    pub proto: String,
    pub bin: String,
    pub count: f64,
    pub bar: String,
}

#[derive(Debug)]
pub struct HbosSummaryRecord {
    pub observe: String,
    pub vlan: i64,
    pub proto: String,
    pub min: f64,
    pub max: f64,
    pub skewness: f64,
    pub avg: f64,
    pub std: f64,
    pub mad: f64,
    pub median: f64,
    pub quantile: f64,
    pub low: f64,
    pub medium: f64,
    pub high: f64,
    pub severe: f64,
    pub filter: String,
}

#[derive(Debug)]
pub struct ParquetHistogramSummaryTable {
    pub column_name: String,
    pub column_type: String,
    pub min: f64,
    pub max: f64,
    pub unique: i64,
    pub avg: f64,
    pub std: f64,
    pub q25: f64,
    pub q50: f64,
    pub q75: f64,
    pub count: usize,
    pub null_percent: f64,
}

#[derive(Debug)]
pub struct HistogramDoubleValue {
    pub boundary: f64,
    pub frequency: usize,
}

#[derive(Debug)]
pub struct HistogramIntegerValue {
    pub boundary: i64,
    pub frequency: usize,
}

#[derive(Debug)]
pub struct IpAddrCategoryRecord {
    pub value: String,
}

#[derive(Debug)]
pub struct NumericCategoryRecord {
    pub value: i64,
}

#[derive(Debug)]
pub struct StringCategoryRecord {
    pub value: String,
}

#[derive(Debug)]
pub struct NumberRecord {
    pub value: i64,
}

#[derive(Debug)]
pub struct TimeCategoryRecord {
    pub value: u64,
}

#[derive(Debug)]
pub struct HbosScoreRecord {
    pub value: f64,
}

#[derive(Debug)]
pub struct HbosQuantile {
    pub value: f64,
}

#[derive(Clone, Debug)]
pub struct DistinctObserveRecord {
    pub observe: String,
    pub vlan: i64,
    pub proto: String,
    pub name: String,
    pub histogram: String,
}

#[derive(Clone, Debug)]
pub struct DistinctObservation {
    pub observe: String,
    pub vlan: i64,
    pub proto: String,
}

#[derive(Clone, Debug)]
pub struct DistinctFeature {
    pub name: String,
}

#[derive(Debug)]
pub struct HistogramSummaryTable {
    pub observe: String,
    pub vlan: i64,
    pub proto: String,
    pub name: String,
    pub histogram: String,
    pub count: usize,
    pub hash_size: u64,
    pub bin_count: usize,
    pub filter: String,
}

#[derive(Debug)]
pub struct NumericHistogramTable {
    pub observe: String,
    pub vlan: i64,
    pub proto: String,
    pub name: String,
    pub key: i64,
    pub value: i64,
}

#[derive(Debug)]
pub struct StringHistogramTable {
    pub observe: String,
    pub vlan: i64,
    pub proto: String,
    pub name: String,
    pub key: String,
    pub value: i64,
}

#[derive(Debug)]
pub struct IpAddrHistogramTable {
    pub observe: String,
    pub vlan: i64,
    pub proto: String,
    pub name: String,
    pub key: u64,
    pub value: u64,
}

#[derive(Debug)]
pub struct TimeHistogramTable {
    pub observe: String,
    pub vlan: i64,
    pub proto: String,
    pub name: String,
    pub key: u32,
    pub value: u64,
}

pub trait TableTrait {
    fn table_name(&self) -> &'static str;
    fn insert(&self, source: &duckdb::Connection, sink: &mut Appender);

    fn purge(&self, api_url: &String, retention_days: u16) {
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
pub static CREATE_METRICS_TABLE: &str = "CREATE TABLE IF NOT EXISTS metrics
(
    stream UINTEGER,
    bucket TIMESTAMP,
    observe VARCHAR,
    name VARCHAR,
    key VARCHAR,
    value UBIGINT
);";

#[derive(Debug)]
pub struct MetricRecord {
    pub stream: u32,
    pub bucket: u64,
    pub observe: String,
    pub name: String,
    pub key: String,
    pub value: f64,
}

#[derive(Debug)]
pub struct MemFlowRecord {
    pub stream: u32,
    pub id: String,
    pub observe: String,
    pub stime: u64,
    pub etime: u64,
    pub dur: u32,
    pub rtt: u32,
    pub pcr: i32,
    pub proto: String,
    pub saddr: String,
    pub daddr: String,
    pub sport: u16,
    pub dport: u16,
    pub iflags: String,
    pub uflags: String,
    pub stcpseq: u32,
    pub dtcpseq: u32,
    pub svlan: u16,
    pub dvlan: u16,
    pub spkts: u64,
    pub dpkts: u64,
    pub sbytes: u64,
    pub dbytes: u64,
    pub sentropy: u8,
    pub dentropy: u8,
    pub siat: u64,
    pub diat: u64,
    pub sstdev: u64,
    pub dstdev: u64,
    pub dtcpurg: u32,
    pub stcpurg: u32,
    pub ssmallpktcnt: u32,
    pub dsmallpktcnt: u32,
    pub slargepktcnt: u32,
    pub dlargepktcnt: u32,
    pub snonemptypktcnt: u32,
    pub dnonemptypktcnt: u32,
    pub sfirstnonemptycnt: u16,
    pub dfirstnonemptycnt: u16,
    pub smaxpktsize: u16,
    pub dmaxpktsize: u16,
    pub sstdevpayload: u16,
    pub dstdevpayload: u16,
    pub spd: String,
    pub reason: String,
    pub smac: String,
    pub dmac: String,
    pub scountry: String,
    pub dcountry: String,
    pub sasn: u32,
    pub dasn: u32,
    pub sasnorg: String,
    pub dasnorg: String,
    pub orient: String,
    //pub tag: Vec<String>,
    pub hbos_score: f64,
    pub hbos_severity: u8,
    //pub hbos_map: Vec<(String, f64)>,
    pub appid: String,
    pub category: String,
    pub risk_bits: u64,
    pub risk_score: u32,
    pub risk_severity: u8,
    //pub risk_list: Vec<String>,
    pub trigger: i8,
}
