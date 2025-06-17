/*
 * Galileo Network Analytics (GNA) Toolkit
 *
 * Copyright 2024 Fidelis Farm & Technologies, LLC
 * All Rights Reserved.
 * See license information in LICENSE.
 */
extern crate pkg_config;

fn main() {
    // compile options
    let src = ["src/ipfix/import_libfixbuf.c", "src/ipfix/export_parquet.c"];
    let mut builder = cc::Build::new();
    let build = builder
        .files(src.iter())
        .include("/usr/include/glib-2.0")
        .include("/usr/lib/x86_64-linux-gnu/glib-2.0/include")
        .include("/usr/local/include")        
        .include("/opt/gnat/include")
        .flag("-Wno-unused-parameter")
        .opt_level(2);
    build.compile("libfixbuf");

    // link options
    println!("cargo:rustc-link-search=/usr/local/lib");  
    println!("cargo:rustc-link-search=/opt/gnat/lib");
    println!("cargo:rustc-link-lib=fixbuf");
    println!("cargo:rustc-link-lib=airframe");
    println!("cargo:rustc-link-lib=ndpi");
    println!("cargo:rustc-link-lib=duckdb");
    println!("cargo:rustc-link-lib=maxminddb");
    println!("cargo:rustc-link-lib=glib-2.0");
}
