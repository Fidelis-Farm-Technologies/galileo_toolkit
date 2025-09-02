use duckdb::{AccessMode, Config, Connection, Error};
use std::env;

pub fn duckdb_open(db_file: &str, mem_gig: u32) -> Result<Connection, duckdb::Error> {
    let mem_threshold = format!("{}GB", mem_gig);
    let cwd = env::current_dir().unwrap();
    let sql_temp_directory = format!("SET max_temp_directory_size = '64GB'");

    let config = Config::default().max_memory(&mem_threshold)?.threads(4)?;

    if db_file == ":memory:" {
        panic!("cannot connect open memory datbase in readonly mode");
    } else if db_file.starts_with("md:") {
        let conn = Connection::open_with_flags(db_file, config)?;
        conn.execute_batch(&sql_temp_directory)?;
        return Ok(conn);
    }

    let conn = Connection::open_with_flags(db_file, config)?;
    conn.execute_batch(&sql_temp_directory)?;
    Ok(conn)
}

pub fn duckdb_open_readonly(db_file: &str, mem_gig: u32) -> Result<Connection, duckdb::Error> {
    let mem_threshold = format!("{}GB", mem_gig);

    let cwd = env::current_dir().unwrap();
    let sql_temp_directory = format!("SET max_temp_directory_size = '64GB'");

    let readonly_config = Config::default()
        .max_memory(&mem_threshold)?
        .threads(4)?
        .access_mode(AccessMode::ReadOnly)?;
    if db_file == ":memory:" {
        panic!("cannot connect open memory datbase in readonly mode");
    } else if db_file.starts_with("md:") {
        let conn = Connection::open_with_flags(db_file, readonly_config)?;
        conn.execute_batch(&sql_temp_directory)?;
        return Ok(conn);
    }

    let conn = Connection::open_with_flags(db_file, readonly_config)?;

    Ok(conn)
}

pub fn duckdb_open_memory(mem_gig: u32) -> Result<Connection, duckdb::Error> {
    let mem_threshold = format!("{}GB", mem_gig);

    let config = Config::default().max_memory(&mem_threshold)?.threads(4)?;

    let conn = Connection::open_in_memory_with_flags(config)?;

    let cwd = env::current_dir().unwrap();
    let sql_temp_directory = format!("SET max_temp_directory_size = '64GB'");

    conn.execute_batch(&sql_temp_directory)?;

    Ok(conn)
}
