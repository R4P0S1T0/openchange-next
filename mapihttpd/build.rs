//! Links liboc_emsmdb only with the `c-backend` feature.
fn main() {
    println!("cargo:rerun-if-env-changed=OC_EMSMDB_LIBDIR");
    if std::env::var_os("CARGO_FEATURE_C_BACKEND").is_none() {
        return;
    }
    let dir = std::env::var("OC_EMSMDB_LIBDIR")
        .expect("OC_EMSMDB_LIBDIR must name the directory holding liboc_emsmdb.so");
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=dylib=oc_emsmdb");
}
