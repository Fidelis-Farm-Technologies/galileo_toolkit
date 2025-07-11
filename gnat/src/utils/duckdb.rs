use duckdb::{AccessMode, Config, Connection};

pub fn duckdb_open(db_file: &str, mem_gig: u32) -> Connection {
    let mem_threshold = format!("{}GB", mem_gig);

    let config = Config::default()
        .max_memory(&mem_threshold)
        .expect("max_memory")
        .threads(4)
        .expect("threads");

    if db_file == ":memory:" {
        panic!("cannot connect open memory datbase in readonly mode");
    } else if db_file.starts_with("md:") {
        let conn = Connection::open_with_flags(db_file, config).expect("opening motherduck");

        conn.execute_batch("SET temp_directory = '/var/spool';")
            .expect("execute_batch");
        return conn;
    }

    let conn = Connection::open_with_flags(db_file, config).expect("opening database");

    conn.execute_batch("SET temp_directory = '/var/spool';")
        .expect("execute_batch");

    conn
}

pub fn duckdb_open_readonly(db_file: &str, mem_gig: u32) -> Connection {
    let mem_threshold = format!("{}GB", mem_gig);

    let readonly_config = Config::default()
        .max_memory(&mem_threshold)
        .expect("max_memory")
        .threads(4)
        .expect("threads")
        .access_mode(AccessMode::ReadOnly)
        .expect("database config");

    if db_file == ":memory:" {
        panic!("cannot connect open memory datbase in readonly mode");
    } else if db_file.starts_with("md:") {
        let conn =
            Connection::open_with_flags(db_file, readonly_config).expect("opening motherduck");

        conn.execute_batch("SET temp_directory = '/var/spool';")
            .expect("execute_batch");

        return conn;
    }

    let conn =
        Connection::open_with_flags(db_file, readonly_config).expect("opening readonly database");
    conn.execute_batch("SET temp_directory = '/var/spool';")
        .expect("execute_batch");

    conn
}

pub fn duckdb_open_memory(mem_gig: u32) -> Connection {
    let mem_threshold = format!("{}GB", mem_gig);
    let config = Config::default()
        .max_memory(&mem_threshold)
        .expect("max_memory")
        .threads(4)
        .expect("threads");
    let conn = Connection::open_in_memory_with_flags(config).expect("opening memory db");

    conn.execute_batch("SET temp_directory = '/var/spool';")
        .expect("execute_batch");

    conn
}
