//! Tests for ModelProcessor in pipeline::model

use super::*;
use crate::pipeline::{Interval, FileType};

#[test]
fn test_model_processor_new_and_process() {
    let command = "modelcmd";
    let input = "input";
    let output = "output";
    let pass = "pass";
    let interval_string = "1h";
    let extension_string = "parquet";
    let options_string = "name=testmodel,features=daddr,quantile=0.5";

    // Should construct without error
    let mut model = ModelProcessor::new(
        command,
        input,
        output,
        pass,
        interval_string,
        extension_string,
        options_string,
    ).expect("ModelProcessor::new should succeed");

    // Test process with empty file list and dummy FileType
    let file_list = vec![];
    let schema_type = FileType::V1;
    let result = model.process(&file_list, schema_type);
    // Should succeed or do nothing if model file does not exist
    assert!(result.is_ok(), "process should succeed on empty file list");
}
