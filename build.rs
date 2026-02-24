use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to re-run if the header changes
    println!("cargo:rerun-if-changed=src/sqlcrypt.h");
    println!("cargo:rerun-if-changed=src/wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("src/wrapper.h")
        // Treat as C++ so `extern "C"` blocks in sqlcrypt.h parse correctly
        .clang_arg("-xc++")
        // Suppress warning for duplicate #define x_cbKeyBlobMaxLen in sqlcrypt.h
        .clang_arg("-Wno-macro-redefined")
        // We implement the exported functions ourselves; only generate types
        .blocklist_function(".*")
        // Generate Rust enums for ergonomic use
        .rustified_enum(".*")
        .derive_debug(true)
        .derive_default(true)
        .derive_copy(true)
        .derive_eq(true)
        .derive_hash(true)
        .derive_ord(true)
        .derive_partialeq(true)
        .derive_partialord(true)
        .generate()
        .expect("Unable to generate bindings from sqlcrypt.h");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
