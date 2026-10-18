//! Resolve a production consumer independently of the workspace's test features.
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Consumer(PathBuf);
impl Drop for Consumer {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn external_client_does_not_resolve_ipir_evaluators() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let consumer = Consumer(std::env::temp_dir().join(format!(
        "native-client-consumer-{}-{unique}",
        std::process::id()
    )));
    fs::create_dir_all(consumer.0.join("src")).unwrap();
    fs::write(
        consumer.0.join("src/lib.rs"),
        "pub use ipir_native_client::NativeRequest;\n",
    )
    .unwrap();
    let package = env!("CARGO_MANIFEST_DIR")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    fs::write(consumer.0.join("Cargo.toml"), format!(
        "[package]\nname = \"native-client-consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n[workspace]\nresolver = \"2\"\n[dependencies]\nipir-native-client = {{ path = \"{package}\" }}\n"
    )).unwrap();
    let output = Command::new(env!("CARGO"))
        .args(["tree", "--offline", "--manifest-path"])
        .arg(consumer.0.join("Cargo.toml"))
        .args(["-e", "normal,build", "--prefix", "none", "--format", "{p}"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "consumer must resolve: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let graph = String::from_utf8(output.stdout).unwrap();
    for forbidden in ["ipir-sp", "simplepir-kernel", "sha1", "clap", "env_logger"] {
        assert!(
            !graph
                .lines()
                .any(|line| line.starts_with(&format!("{forbidden} v"))),
            "native client must not depend on {forbidden}"
        );
    }
    assert!(
        graph.lines().any(|line| line.starts_with("reinspiring v")),
        "shared native arithmetic remains available"
    );
}
