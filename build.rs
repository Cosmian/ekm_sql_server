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
        // bindgen opaque-izes _GUID in C++ mode; provide the correct definition manually
        .blocklist_type("_GUID")
        .blocklist_type("GUID")
        .raw_line(
            "#[repr(C)]\n\
             #[derive(Debug, Default, Copy, Clone, Hash, PartialOrd, Ord, PartialEq, Eq)]\n\
             pub struct _GUID {\n\
             \x20   pub Data1: u32,\n\
             \x20   pub Data2: u16,\n\
             \x20   pub Data3: u16,\n\
             \x20   pub Data4: [u8; 8usize],\n\
             }\n\
             pub type GUID = _GUID;",
        )
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
