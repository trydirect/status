use assert_cmd::Command;

fn expected_version_output() -> String {
    let base = env!("CARGO_PKG_VERSION");
    let git_hash = std::process::Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    match git_hash {
        Some(hash) => format!("{base} ({hash})"),
        None => base.to_string(),
    }
}

#[test]
fn status_version_prints_display_version_only() {
    let mut cmd = Command::cargo_bin("status").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(format!("{}\n", expected_version_output()))
        .stderr("");
}

#[test]
fn status_short_version_flag_prints_display_version_only() {
    let mut cmd = Command::cargo_bin("status").unwrap();
    cmd.arg("-V")
        .assert()
        .success()
        .stdout(format!("{}\n", expected_version_output()))
        .stderr("");
}
