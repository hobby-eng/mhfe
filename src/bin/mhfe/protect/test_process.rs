//! Isolate process-policy probes from the test runner and its other tests.

use std::process::{Command, Output};

pub(crate) const TARGET_PID: &str = "MHFE_PUBLIC_PROBE_PID";

pub(crate) fn run(name: &str, target: Option<u32>) -> Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--ignored", "--exact", name, "--nocapture"]);
    if let Some(pid) = target {
        command.env(TARGET_PID, pid.to_string());
    }
    command.output().unwrap()
}

pub(crate) fn require_success(output: Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    // An exact filter that matches no test also exits successfully. Require the pinned Rust
    // test harness's one-test success summary so a renamed probe cannot silently stop running.
    assert!(
        output.status.success()
            && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "{}\n{}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_child_test_is_not_accepted() {
        let result = std::panic::catch_unwind(|| {
            require_success(run("protect::test_process::tests::no_such_probe", None));
        });
        assert!(result.is_err());
    }
}
