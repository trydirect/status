//! The generated Homebrew formula must survive `brew audit --strict`.
//!
//! Regression for the PR #140 review: `license "MIT OR Apache-2.0"` is parsed
//! by Homebrew as one bogus SPDX identifier instead of an expression, so the
//! generated formula failed license validation. Homebrew expresses dual
//! licensing with the alternatives syntax instead.

use std::process::Command;

fn render_formula() -> String {
    let output = Command::new("scripts/render-homebrew-formula.sh")
        .args(["9.9.9", "/dev/stdout"])
        .envs([
            ("SHA256_AARCH64_APPLE_DARWIN", "a".repeat(64)),
            ("SHA256_X86_64_APPLE_DARWIN", "b".repeat(64)),
            ("SHA256_AARCH64_UNKNOWN_LINUX_MUSL", "c".repeat(64)),
            ("SHA256_X86_64_UNKNOWN_LINUX_MUSL", "d".repeat(64)),
        ])
        .output()
        .expect("render-homebrew-formula.sh should run");
    assert!(
        output.status.success(),
        "render script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn homebrew_formula_uses_any_of_for_the_dual_license() {
    let formula = render_formula();

    assert!(
        formula.contains("license any_of: [\"MIT\", \"Apache-2.0\"]"),
        "the formula must express the dual license with Homebrew's alternatives \
         syntax, or `brew audit --strict` rejects it; got:\n{}",
        formula
            .lines()
            .find(|line| line.trim_start().starts_with("license"))
            .unwrap_or("(no license line)")
    );
    assert!(
        !formula.contains("license \"MIT OR Apache-2.0\""),
        "Homebrew parses a single `license \"...\"` string as one SPDX identifier, \
         not as an SPDX expression"
    );
}
