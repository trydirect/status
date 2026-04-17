fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/pipe.proto");
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["proto/pipe.proto"], &["proto"])?;
    Ok(())
}
