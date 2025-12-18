fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("Failed to find bundled protoc");

    std::env::set_var("PROTOC", protoc);

    let mut cfg = prost_build::Config::new();
    cfg.out_dir(out_dir);
    cfg.compile_protos(&["wire.proto"], &["."])
        .expect("Failed to compile protos");
}
