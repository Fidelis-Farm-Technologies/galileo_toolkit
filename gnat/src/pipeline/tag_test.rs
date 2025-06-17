//! Tests for TagProcessor in pipeline::tag

use super::*;
use crate::pipeline::{Interval, FileType};

#[test]
fn test_tag_processor_new_and_tag_list() {
    let command = "tagcmd";
    let input = "input";
    let output = "output";
    let pass = "pass";
    let interval_string = "1h";
    let extension_string = "parquet";
    let options_string = "tag=nonexistent_tag_file";

    // Should construct, but will panic on missing tag file
    let result = std::panic::catch_unwind(|| {
        TagProcessor::new(
            command,
            input,
            output,
            pass,
            interval_string,
            extension_string,
            options_string,
        )
    });
    assert!(result.is_err(), "TagProcessor::new should panic on missing tag file");
}
