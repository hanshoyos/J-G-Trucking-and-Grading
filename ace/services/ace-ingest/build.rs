fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Proto compilation requires protoc.  In Phase 1 the hot path uses JSON
    // serialisation so this step is optional.  Set SKIP_PROTO_BUILD=1 to
    // skip (useful in environments without protoc installed).
    if std::env::var("SKIP_PROTO_BUILD").is_ok() {
        return Ok(());
    }

    let proto_root = "../../proto";

    match prost_build::compile_protos(
        &[
            &format!("{proto_root}/ace_cef.proto"),
            &format!("{proto_root}/services/ingest.proto"),
        ],
        &[proto_root],
    ) {
        Ok(()) => {}
        Err(e) => {
            // Warn but don't abort — the binary can compile fine without
            // generated proto types in Phase 1.
            println!("cargo:warning=Proto compilation skipped (protoc unavailable?): {e}");
        }
    }

    println!("cargo:rerun-if-changed={proto_root}");
    Ok(())
}
