/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

extern crate c_string;
extern crate libc;

use std::ffi::CString;
use std::fs;
use std::os::raw::c_char;
use std::path::Path;
use std::thread;
use std::time::Duration;

// C functions wrappering libfixbuf operations
extern "C" {
    fn yaf_collect(
        observation: *const c_char,
        input_file: *const c_char,
        output_file: *const c_char,
        asn_file: *const c_char,
        country_file: *const c_char,
    ) -> i32;
}

fn safe_yaf_collect(
    observation: &String,
    input_file: &String,
    output_file: &String,
    asn_file: &String,
    country_file: &String,
) -> i32 {
    let c_observation = CString::new(observation.as_str()).expect("converting to c_string");
    let c_input_file = CString::new(input_file.as_str()).expect("converting to c_string");
    let c_output_file = CString::new(output_file.as_str()).expect("converting to c_string");
    let c_asn_file = CString::new(asn_file.as_str()).expect("converting to c_string");
    let c_country_file = CString::new(country_file.as_str()).expect("converting to c_string");
    unsafe {
        return yaf_collect(
            c_observation.as_c_str().as_ptr(),
            c_input_file.as_c_str().as_ptr(),
            c_output_file.as_c_str().as_ptr(),
            c_asn_file.as_c_str().as_ptr(),
            c_country_file.as_c_str().as_ptr(),
        );
    };
}

pub fn collect(
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
    
    let status = safe_yaf_import(
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
        
    Ok(())
}
