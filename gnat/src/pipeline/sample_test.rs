//! Tests for SampleProcessor in pipeline::sample

use super::*;
use crate::pipeline::{Interval, FileType};

#[test]
fn test_sample_processor_new_and_process() {
    let command = "samplecmd";
    let input = "input";
    let output = "output";
    let pass = "pass";
    let interval_string = "1h";
    let extension_string = "parquet";
    let options_string = "retention=7,percent=20";

    // Should construct without error
    let mut sample = SampleProcessor::new(
        command,
        input,
        output,
        pass,
        interval_string,
        extension_string,
        options_string,
    ).expect("SampleProcessor::new should succeed");

    // Test process with empty file list and dummy FileType
    let file_list = vec![];
    let schema_type = FileType::V1;
    let result = sample.process(&file_list, schema_type);
    // Should succeed or do nothing if no files
    assert!(result.is_ok(), "process should succeed on empty file list");
}
