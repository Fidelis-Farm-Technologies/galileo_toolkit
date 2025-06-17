//! Tests for HbosProcessor in pipeline::hbos

use super::*;
use crate::pipeline::{Interval, FileType};

#[test]
fn test_hbos_processor_new() {
    let command = "hboscmd";
    let input = "input";
    let output = "output";
    let pass = "pass";
    let interval_string = "1h";
    let extension_string = "parquet";
    let options_string = "model=nonexistent_model_file";

    // Should construct without error, even if model file does not exist
    let hbos = HbosProcessor::new(
        command,
        input,
        output,
        pass,
        interval_string,
        extension_string,
        options_string,
    );
    assert!(hbos.is_ok(), "HbosProcessor::new should succeed");
    let mut hbos = hbos.unwrap();

    // load_hbos_summary should return an error for missing file
    let result = hbos.load_hbos_summary();
    assert!(result.is_err(), "load_hbos_summary should fail for missing file");
}
