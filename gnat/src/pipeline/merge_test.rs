//! Tests for MergeProcessor in pipeline::merge

use super::*;
use crate::pipeline::{FileType, Interval};
use duckdb::Connection;
use duckdb::Connection;

#[test]
fn test_merge_processor_new_and_process() {
    let command = "testcmd";
    let input = "input";
    let output = "output";
    let pass = "pass";
    let interval_string = "1h";
    let extension_string = "parquet";
    let options_string = "";

    // Should construct without error
    let mut merge = MergeProcessor::new(
        command,
        input,
        output,
        pass,
        interval_string,
        extension_string,
        options_string,
    )
    .expect("MergeProcessor::new should succeed");

    // Test process with empty file list and dummy FileType
    let file_list = vec![];
    let schema_version = FileType::V1;
    let result = merge.process(&file_list, schema_version);
    assert!(result.is_ok(), "process should succeed on empty file list");
}
