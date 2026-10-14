// AUD-024 guide-lib-core probe: copies the non-test part of the reviewed src/engine/cgroup.rs,
// without its inner doc comment and with `pub(super)` opened, into OUT_DIR, so that the
// cgroup_usage probe calls the reviewed functions themselves. MHFE_ROOT names the repository.
use std::{env, fs, path::PathBuf};

fn main() {
    let root = env::var("MHFE_ROOT").expect("MHFE_ROOT names the repository");
    let source = PathBuf::from(root).join("src/engine/cgroup.rs");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-env-changed=MHFE_ROOT");
    let text = fs::read_to_string(&source).expect("src/engine/cgroup.rs");
    let body: Vec<String> = text
        .split("#[cfg(test)]")
        .next()
        .expect("the file has code")
        .lines()
        .filter(|line| !line.starts_with("//!"))
        .map(|line| line.replace("pub(super) ", "pub "))
        .collect();
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("cgroup_copy.rs");
    fs::write(out, body.join("\n")).expect("write the copy");
}
