/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::ipfix::libfixbuf::safe_ipfix_file_import;

use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

pub fn aggregate(
    observation_tag: &String,
    input_spec: &String,
    output_spec: &String,
    processed_spec: &String,
    polling: bool,
    asn_spec: &String,
    country_spec: &String,
) -> Result<(), std::io::Error> {
    println!("\tobservation: {}", observation_tag);
    println!("\tinput spec: {}", input_spec);
    println!("\toutput spec: {}", output_spec);
    println!("\tprocessed spec: {}", processed_spec);
    println!("\tasn file: {}", asn_spec);
    println!("\tcountry file: {}", country_spec);
    println!("\tpolling: {}", polling);

    if Path::new(input_spec).is_file() {
        let status = safe_ipfix_file_import(
            &observation_tag,
            &input_spec,
            &output_spec,
            &asn_spec,
            &country_spec,
        );
        if status < 0 {
            eprintln!("error: processing {}", input_spec);
            std::process::exit(exitcode::DATAERR);
        }
    } else {
        let poll_interval = Duration::from_millis(1000);
        println!("import scanner: running [{}]", input_spec);
        loop {
            let mut counter = 0;
            let mut processed_path;

            for entry in fs::read_dir(input_spec)? {
                let file: fs::DirEntry = entry.unwrap();
                let file_name = String::from(file.file_name().to_string_lossy());
                let src_path = String::from(file.path().to_string_lossy());

                if file_name.starts_with(observation_tag) && file_name.ends_with(".yaf") {
                    let lock_path = format!("{}.lock", src_path);
                    if Path::new(lock_path.as_str()).exists() {
                        continue;
                    }
                    let status = safe_ipfix_file_import(
                        &observation_tag,
                        &src_path,
                        &output_spec,
                        &asn_spec,
                        &country_spec,
                    );
                    if status < 0 {
                        eprintln!(
                            "error: processing {}; moving to {}",
                            src_path, processed_spec
                        );
                        processed_path = format!("{}/{}.err", processed_spec, file_name);
                    } else {
                        processed_path = format!("{}/{}", processed_spec, file_name);
                    }
                    if !processed_spec.is_empty() {
                        match fs::rename(src_path.clone(), processed_path.clone()) {
                            Ok(c) => c,
                            Err(e) => {
                                panic!("error: moving {} -> {}: {:?}", src_path, processed_path, e)
                            }
                        };
                    }
                    counter += 1;
                }
            }

            if !polling {
                break;
            }
            if counter == 0 {
                thread::sleep(poll_interval);
            }
        }
    }
    Ok(())
}
