//! Isolate process-policy probes from the test runner and its other tests.

use std::process::{Command, Output};

pub(super) const TARGET_PID: &str = "MHFE_PUBLIC_PROBE_PID";

pub(super) fn run(name: &str, target: Option<u32>) -> Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--ignored", "--exact", name, "--nocapture"]);
    if let Some(pid) = target {
        command.env(TARGET_PID, pid.to_string());
    }
    command.output().unwrap()
}

pub(super) fn require_success(output: Output) {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
