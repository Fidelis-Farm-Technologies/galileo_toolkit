/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024-2025
 * Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

use crate::pipeline::check_parquet_stream;
use crate::pipeline::load_environment;
use crate::pipeline::parse_interval;
use crate::pipeline::parse_options;
use crate::pipeline::FileProcessor;

use crate::pipeline::Interval;
use crate::pipeline::StreamType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Error;
use std::path::Path;

#[derive(Clone, Serialize, Deserialize)]
pub struct InputJsonStructure {
    input: String,
}

pub struct MergeProcessor {
    pub command: String,
    pub input_list: Vec<String>,
    pub output_list: Vec<String>,
    pub pass: String,
    pub interval: Interval,
    pub extension: String,
}

impl MergeProcessor {
    pub fn new(
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
        let options = parse_options(options_string);

        for (key, value) in &options {
            if !value.is_empty() {
                println!("{}: [{}={}]", command, key, value);
            }
        }

        if !Path::new(input).is_file() {
            return Err(Error::other("input is not a JSON file"));
        }

        let mut input_list = Vec::<String>::new();
        Self::load_json_file(input, &mut input_list)?;
        let mut output_list = Vec::<String>::new();
        output_list.push(output.to_string());
        Ok(Self {
            command: command.to_string(),
            input_list: input_list,
            output_list: output_list,
            pass: pass.to_string(),
            interval: interval,
            extension: extension_string.to_string(),
        })
    }
    fn load_json_file(input_spec: &str, input_list: &mut Vec<String>) -> Result<(), Error> {
        let json_data: String = fs::read_to_string(input_spec).expect("unable to read JSON file");
        let input_directories: Vec<InputJsonStructure> =
            serde_json::from_str(&json_data).expect("failed to parse input file");

        if input_directories.is_empty() {
            return Err(Error::other("no directories in input file"));
        }
        let mut collison_map = HashMap::new();
        for dir in input_directories {
            if collison_map.insert(dir.input.clone(), "x").is_none() {
                println!("\tinput: [{}]", dir.input);
                input_list.push(dir.input);
            } else {
                println!("\t{} (duplicate)", dir.input);
            }
        }

        Ok(())
    }
}
impl FileProcessor for MergeProcessor {
    fn get_command(&self) -> &String {
        &self.command
    }
    fn get_input(&self, input_list: &mut Vec<String>) -> Result<(), Error> {
        *input_list = self.input_list.clone();
        Ok(())
    }
    fn get_output(&self, output_list: &mut Vec<String>) -> Result<(), Error> {
        *output_list = self.output_list.clone();
        Ok(())
    }
    fn get_pass(&self) -> &String {
        &self.pass
    }
    fn get_interval(&self) -> &Interval {
        &self.interval
    }
    fn get_stream_id(&self) -> u32 {
        StreamType::ADHOC as u32
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
        // Use iterator and join for file list formatting
        let parquet_list = file_list
            .iter()
            .map(|file| format!("'{}'", file))
            .collect::<Vec<_>>()
            .join(",");
        let parquet_list = format!("[{}]", parquet_list);

        // Check if the parquet files are valid
        // If not, skip processing
        // This is a performance optimization to avoid processing invalid files
        // If the files are not valid, we will not be able to read them
        // and will end up with an empty table
        if let Ok(status) = check_parquet_stream(&parquet_list) {
            if status == false {
                eprintln!(
                    "{}: invalid stream of parquet files, skipping",
                    self.command
                );
                return Ok(());
            }
        }

        let record_count = self.forward(&parquet_list, &self.output_list.clone())?;
        if record_count > 0 {
            println!("{}: {} flows merged", self.command, record_count);
        } else {
            println!("{}: no flows merged", self.command);
        }
        Ok(())
    }
}
