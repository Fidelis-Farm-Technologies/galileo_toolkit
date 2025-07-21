pub mod histogram_model;
pub mod ipaddr_category;
pub mod number;
pub mod numeric_category;
pub mod string_category;
pub mod time_category;

#[derive(Debug)]
pub enum HistogramType {
    Numerical,
    NumericCategory,
    StringCategory,
    IpNetworkCategory,
    Nothing(i32),
}

pub const DEFAULT_FREQUENCY_BIN_SIZE: usize = 100;
pub const DEFAULT_VLAN_MODULUS: i64 = 1024;
pub const DEFAULT_NETWORK_MODULUS: u64 = 8192;
pub const DEFAULT_PORT_MODULUS: i64 = 8192;
pub const DEFAULT_ENTROPY_MODULUS: i64 = 256;
pub const DEFAULT_PCR_MODULUS: i64 = 256;
pub const DEFAULT_ASN_MODULUS: i64 = 8192;
pub const NO_MODULUS: i64 = 0;
pub const MINIMUM_DAYS: u32 = 2;

pub static MODEL_SUMMARY: &str = "CREATE TABLE IF NOT EXISTS model_summary
(
    observe VARCHAR,
    vlan INTEGER,
    proto VARCHAR,
    name VARCHAR,
    min FLOAT,
    max FLOAT,
    skewness FLOAT,
    avg FLOAT,
    stdev FLOAT,
    mad FLOAT,
    median FLOAT,                
    count UBIGINT,
);";
pub static MODEL_DISTINCT_FEATURE: &str =
    "SELECT DISTINCT name FROM histogram_summary GROUP BY ALL ORDER BY ALL;";
pub static PARQUET_DISTINCT_OBSERVATIONS: &str = "SELECT DISTINCT observe, dvlan, proto FROM flow WHERE proto='tcp' OR proto='udp' GROUP BY ALL ORDER BY ALL;";
pub static MODEL_DISTINCT_OBSERVATIONS: &str =
    "SELECT DISTINCT observe, vlan, proto FROM histogram_summary GROUP BY ALL ORDER BY ALL;";
pub static HISTOGRAM_DISTINCT: &str =  "SELECT DISTINCT observe,vlan,proto,name,histogram FROM histogram_summary GROUP BY ALL ORDER BY ALL;";
pub static HISTOGRAM_SUMMARY: &str = "CREATE TABLE IF NOT EXISTS histogram_summary
(
    observe VARCHAR,
    vlan INTEGER,
    proto VARCHAR,
    name VARCHAR,
    histogram VARCHAR,               
    count UBIGINT,
    hash_size INTEGER,
    bin_count UBIGINT,
    filter VARCHAR
);";

static HISTOGRAM_NUMERICAL: &str = "CREATE TABLE IF NOT EXISTS histogram_numerical
(
    observe VARCHAR,
    vlan INTEGER,
    proto VARCHAR,
    name VARCHAR,             
    key BIGINT,
    value BIGINT
);";
static HISTOGRAM_NUMERIC_CATEGORY: &str = "CREATE TABLE IF NOT EXISTS histogram_numeric_category
(
    observe VARCHAR,
    vlan INTEGER,
    proto VARCHAR,
    name VARCHAR,             
    key BIGINT,
    value BIGINT
);";
static HISTOGRAM_STRING_CATEGORY: &str = "CREATE TABLE IF NOT EXISTS histogram_string_category
(
    observe VARCHAR,
    vlan INTEGER,
    proto VARCHAR,
    name VARCHAR,             
    key VARCHAR,
    value BIGINT
)";
static HISTOGRAM_IPADDR_CATEGORY: &str = "CREATE TABLE IF NOT EXISTS histogram_ipaddr_category
(
    observe VARCHAR,
    vlan INTEGER,
    proto VARCHAR,
    name VARCHAR,             
    key UBIGINT,
    value UBIGINT
);";
static HISTOGRAM_TIME_CATEGORY: &str = "CREATE TABLE IF NOT EXISTS histogram_time_category
(
    observe VARCHAR,
    vlan INTEGER,
    proto VARCHAR,
    name VARCHAR,             
    key BIGINT,
    value BIGINT
);";

pub static HBOS_SUMMARY: &str = "CREATE TABLE IF NOT EXISTS hbos_summary
(
    observe VARCHAR,
    vlan INTEGER,
    proto VARCHAR,
    min FLOAT,
    max FLOAT,
    skewness FLOAT,
    avg FLOAT,
    stdev FLOAT,
    mad FLOAT,
    median FLOAT,
    quantile FLOAT,
    low FLOAT,
    medium FLOAT,
    high FLOAT,
    severe FLOAT
);";

static HBOS_SCORE: &str = "CREATE OR REPLACE TABLE hbos_score
(
    score FLOAT
)";

pub static MD_FLOW_TABLE: &str = "CREATE TABLE IF NOT EXISTS flow (
    stream UINTEGER,
    id UUID,
    observe VARCHAR,
    stime TIMESTAMP,
    etime TIMESTAMP,
    dur UINTEGER,
    rtt UINTEGER,
    pcr INTEGER,
    proto VARCHAR,
    saddr VARCHAR,
    daddr VARCHAR,
    sport USMALLINT,
    dport USMALLINT,
    iflags VARCHAR,
    uflags VARCHAR,
    stcpseq UINTEGER,
    dtcpseq UINTEGER,
    svlan USMALLINT,
    dvlan USMALLINT,
    spkts UBIGINT,
    dpkts UBIGINT,
    sbytes UBIGINT,
    dbytes UBIGINT,
    sentropy UTINYINT,
    dentropy UTINYINT,
    siat UBIGINT,
    diat UBIGINT,
    sstdev UBIGINT,
    dstdev UBIGINT,
    stcpurg UINTEGER,
    dtcpurg UINTEGER,
    ssmallpktcnt UINTEGER,
    dsmallpktcnt UINTEGER,
    slargepktcnt UINTEGER,
    dlargepktcnt UINTEGER,
    snonemptypktcnt UINTEGER,
    dnonemptypktcnt UINTEGER,
    sfirstnonemptycnt USMALLINT,
    dfirstnonemptycnt USMALLINT,
    smaxpktsize USMALLINT,
    dmaxpktsize USMALLINT,    
    sstdevpayload USMALLINT,
    dstdevpayload USMALLINT,
    spd VARCHAR,
    reason VARCHAR,
    smac VARCHAR,
    dmac VARCHAR,
    scountry VARCHAR,
    dcountry VARCHAR,
    sasn UINTEGER,
    dasn UINTEGER,
    sasnorg VARCHAR,
    dasnorg VARCHAR,
    orient VARCHAR,   
    tag VARCHAR[],
    hbos_score DOUBLE,
    hbos_severity UTINYINT,
    hbos_map MAP(VARCHAR, FLOAT),
    ndpi_appid VARCHAR,
    ndpi_category VARCHAR,
    ndpi_risk_bits UBIGINT,   
    ndpi_risk_score UINTEGER,
    ndpi_risk_severity UTINYINT,
    ndpi_risk_list VARCHAR[],
    trigger TINYINT
    )";
