/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::ipfix::libfixbuf::unsafe_ipfix_file_import;
use crate::pipeline::load_environment;
use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;
use crate::pipeline::FileType;
use crate::pipeline::Interval;
use crate::pipeline::StreamType;
use duckdb::Connection;
use std::io::Error;
use std::path::Path;

pub struct ImportProcessor {
    pub command: String,
    pub input: String,
    pub output: String,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
    pub observation: String,
    pub asn: String,
    pub country: String,
}

impl ImportProcessor {
    pub fn new<'a>(
        command: &str,
        input: &str,
        output: &str,
        pass: &str,
        interval_string: &str,
        extension_string: &str,
        options_string: &str,
    ) -> Result<Self, Error> {
        let _ = load_environment();
        let interval = parse_interval(interval_string);
        let mut options = parse_options(options_string);
        options.entry("observation").or_insert("gnat");
        options.entry("asn").or_insert("");
        options.entry("country").or_insert("");
        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}={}]", command, key, value);
            }
        }

        let observation = options.get("observation").expect("expected observation");
        let asn = options.get("asn").expect("expected asn");
        if !asn.is_empty() {
            let asn_path = Path::new(&asn);
            if !asn_path.exists() {
                return Err(Error::other("invalid ASN database path"));
            }
        }
        let country = options.get("country").expect("expected country");
        if !country.is_empty() {
            let country_path = Path::new(&country);
            if !country_path.exists() {
                return Err(Error::other("invalid COUNTRY database path"));
            }
        }
        Ok(Self {
            command: command.to_string(),
            input: input.to_string(),
            output: output.to_string(),
            pass: pass.to_string(),
            interval,
            extension: extension_string.to_string(),
            observation: observation.to_string(),
            asn: asn.to_string(),
            country: country.to_string(),
        })
    }
}
impl FileProcessor for ImportProcessor {
    fn get_command(&self) -> &String {
        &self.command
    }
    fn get_input(&self) -> &String {
        &self.input
    }
    fn get_output(&self) -> &String {
        &self.output
    }
    fn get_pass(&self) -> &String {
        &self.pass
    }
    fn get_interval(&self) -> &Interval {
        &self.interval
    }
    fn get_stream_id(&self) -> u32 {
        StreamType::IPFIX as u32
    }
    fn get_file_extension(&self) -> &String {
        &self.extension
    }
    fn socket(&mut self) -> Result<(), Error> {
        Err(Error::other("socket function unsupported"))
    }
    fn delete_files(&self) -> bool {
        true
    }
    fn process(&mut self, file_list: &Vec<String>) -> Result<(), Error> {
        for file in file_list.iter() {
            let mut observation = self.observation.clone();
            if let Some(i) = file.find('-') {
                if i > 0 {
                    observation = file[..i].to_string();
                }
            }

            let import_result = unsafe_ipfix_file_import(
                &self.command,
                file,
                &self.output,
                &observation,
                &self.asn,
                &self.country,
            );
            if import_result != 0 {
                return Err(Error::other(format!("import failed for file: {}", file)));
            }
        }
        Ok(())
    }
}
