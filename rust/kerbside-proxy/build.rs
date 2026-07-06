use std::path::Path;

fn main() {
    // Use the vendored protoc so the build needs no system protoc package.
    // protoc-bin-vendored ships the binary in the build-dependency crate, so
    // this resolves a real path with no network access at build time.
    std::env::set_var(
        "PROTOC",
        protoc_bin_vendored::protoc_bin_path().expect("locate vendored protoc"),
    );

    // The proto is referenced in-tree so the Rust and Python stubs never
    // diverge from a single source. The crate lives at rust/kerbside-proxy/,
    // so the repo root is two levels up. This couples the crate build to the
    // repo layout, which is acceptable since they live in the same repo.
    let proto_dir = "../../kerbside/rpc";
    let proto = "../../kerbside/rpc/kerbside.proto";

    assert!(
        Path::new(proto).exists(),
        "kerbside.proto not found at {proto}; the crate build must run with \
         the repo root available (see the Makefile: it mounts the repo root \
         and sets the workdir to rust/kerbside-proxy)"
    );

    tonic_build::configure()
        // We are a client of the KerbsideProxy service, not a server.
        .build_server(false)
        .build_client(true)
        // tonic-build 0.12 renamed compile() to compile_protos().
        .compile_protos(&[proto], &[proto_dir])
        .expect("compile kerbside.proto");

    println!("cargo:rerun-if-changed={proto}");
}
