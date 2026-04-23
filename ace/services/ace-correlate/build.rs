fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("SKIP_PROTO_BUILD").is_ok() {
        return Ok(());
    }

    let proto_root = "../../proto";

    match prost_build::compile_protos(
        &[
            &format!("{proto_root}/ace_cef.proto"),
            &format!("{proto_root}/services/correlate.proto"),
        ],
        &[proto_root],
    ) {
        Ok(()) => {}
        Err(e) => {
            println!("cargo:warning=Proto compilation skipped (protoc unavailable?): {e}");
        }
    }

    println!("cargo:rerun-if-changed={proto_root}");
    Ok(())
}
