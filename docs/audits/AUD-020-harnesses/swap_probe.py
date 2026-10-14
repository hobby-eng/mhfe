"""Emit a bounded Rust probe of the exact current swap-inventory helper, with no secrets."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def main():
    path = ROOT / "src/bin/mhfe/protect.rs"
    source = path.read_text()
    start = source.index("fn unprotected_swap_under(")
    end = source.index("\n/// The kernel's name of the block device", start)
    helper = source[start:end]
    # Device resolution is irrelevant on the failing read branch. For the positive control,
    # the stubs classify a synthetic device as unknown without probing the real machine.
    prelude = """use std::{fs, path::{Path, PathBuf}};
#[derive(Debug)] struct SwapArea { name: String, unknown: bool }
fn device_of_node(_: &Path, _: &str) -> Option<String> { None }
fn device_of_file(_: &Path, _: &str) -> Option<String> { None }
fn encrypted(_: &Path, _: &str, _: usize) -> bool { false }
"""
    driver = """
fn main() {
    let root = PathBuf::from(std::env::args().nth(1).expect("synthetic workspace"));
    assert!(!root.exists(), "do not overwrite an existing probe case");
    fs::create_dir_all(root.join("proc")).unwrap();
    let missing = unprotected_swap_under(&root).len();
    fs::write(root.join("proc/swaps"), "Filename Type Size Used Priority\\n").unwrap();
    let empty = unprotected_swap_under(&root).len();
    fs::write(root.join("proc/swaps"), "Filename Type Size Used Priority\\n/dev/mock partition 1024 0 -2\\n").unwrap();
    let visible = unprotected_swap_under(&root).len();
    fs::remove_file(root.join("proc/swaps")).unwrap();
    fs::create_dir(root.join("proc/swaps")).unwrap();
    let unreadable = unprotected_swap_under(&root).len();
    assert_eq!((missing, empty, visible, unreadable), (0, 0, 1, 0));
    println!("missing_inventory={} known_empty={} visible_unknown_swap={} unreadable_inventory={}", missing, empty, visible, unreadable);
}
"""
    print(json.dumps({"sourceSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                      "helperSha256": hashlib.sha256(helper.encode()).hexdigest(),
                      "code": prelude + helper + driver,
                      "limitation": "Exact helper; synthetic metadata only; no Argon2, paging or secret extraction."}))


if __name__ == "__main__":
    main()
