//! Tests for ImportProcessor in pipeline::import

use super::*;
use crate::pipeline::{Interval, FileType};

#[test]
fn test_import_processor_new_and_process() {
    let command = "importcmd";
    let input = "input";
    let output = "output";
    let pass = "pass";
    let interval_string = "1h";
    let extension_string = "yaf";
    let options_string = "observation=testobs";

    // Should construct without error
    let mut import = ImportProcessor::new(
        command,
        input,
        output,
        pass,
        interval_string,
        extension_string,
        options_string,
    ).expect("ImportProcessor::new should succeed");

    // Test process with empty file list and FileType::IPFIX_YAF
    let file_list = vec![];
    let schema_type = FileType::IPFIX_YAF;
    let result = import.process(&file_list, schema_type);
    assert!(result.is_ok(), "process should succeed on empty file list");
}
