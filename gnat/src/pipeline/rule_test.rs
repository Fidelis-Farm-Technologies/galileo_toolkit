//! Tests for RuleProcessor in pipeline::rule

use super::*;
use crate::pipeline::{Interval, FileType};

#[test]
fn test_rule_processor_new_and_load_configuration() {
    let command = "rulecmd";
    let input = "input";
    let output = "output";
    let pass = "pass";
    let interval_string = "1h";
    let extension_string = "parquet";
    let options_string = "model=nonexistent_model_file,rule=nonexistent_rule_file";

    // Should construct without error, even if model/rule file does not exist
    let rule = RuleProcessor::new(
        command,
        input,
        output,
        pass,
        interval_string,
        extension_string,
        options_string,
    );
    assert!(rule.is_ok(), "RuleProcessor::new should succeed");
    let mut rule = rule.unwrap();

    // load_configuration should return an error for missing files
    let result = rule.load_configuration();
    assert!(result.is_err(), "load_configuration should fail for missing files");
}
