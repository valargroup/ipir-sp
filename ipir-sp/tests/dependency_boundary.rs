//! Library consumers do not need the demonstration binaries' logging or argument parser.
use std::process::Command;

#[test]
fn default_library_graph_omits_demo_dependencies() {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--locked",
            "--offline",
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            "-p",
            "ipir-sp",
            "-e",
            "normal,build",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ])
        .output()
        .expect("Cargo can inspect the locked library graph");
    assert!(
        output.status.success(),
        "library dependencies resolve: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let graph = String::from_utf8(output.stdout).expect("Cargo reports UTF-8 package names");
    for dependency in ["env_logger", "clap"] {
        assert!(
            !graph
                .lines()
                .any(|line| line.starts_with(&format!("{dependency} v"))),
            "library graph must omit demonstration dependency {dependency}"
        );
    }
}
