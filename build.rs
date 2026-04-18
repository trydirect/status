fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/pipe.proto");
    // Vendor protoc so builds work without a system-installed protoc
    let _protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc not found");
    std::env::set_var("PROTOC", &_protoc);
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["proto/pipe.proto"], &["proto"])?;
    Ok(())
}
