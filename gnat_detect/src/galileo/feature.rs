/*
 * Galileo Network Analytics (GNA) Toolkit
 * 
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */

 /* 
use anyhow::Result;
use tch::{nn, nn::Module, nn::OptimizerConfig, Kind, Reduction, Tensor};
use std::sync::mpsc::{Receiver, SyncSender};
*/


pub fn feature(input_spec: &String, output_spec: &String, processed_spec: &String, poll: bool) {
    println!("input directory: {}", input_spec);
    println!("output directory: {}", output_spec);
    println!("archive directory: {}", processed_spec);
}
