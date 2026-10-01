"""Execute the unchanged macOS page-summing expression on an Apple-contract fixture.

This is an arithmetic contract probe on Linux, not a native macOS memory-pressure test.
XNU counts speculative pages within free_count. No memory-heavy allocation occurs.
"""
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
source = (ROOT / "src/engine/ffi.rs").read_text()
expression = re.search(r"let pages = (.*?);\n    pages.checked_mul\(page_size\)", source, re.S).group(1)
fixture = """
struct Statistics { free_count: u32, inactive_count: u32, purgeable_count: u32, speculative_count: u32 }
fn main() {
    // 1 GiB free_count, including 0.5 GiB speculative; another 0.5 GiB inactive.
    let statistics = Statistics { free_count: 262144, inactive_count: 131072, purgeable_count: 0, speculative_count: 131072 };
    let page_size = 4096_u64;
    let pages = EXPRESSION;
    let reported = pages.checked_mul(page_size).unwrap();
    let without_duplicate = (u64::from(statistics.free_count) + u64::from(statistics.inactive_count)) * page_size;
    println!("Reported bytes: {reported}; free plus inactive bytes: {without_duplicate}");
    println!("Default 2 GiB admission: reported={}, without duplicate={}", reported >= 2_u64.pow(31), without_duplicate >= 2_u64.pow(31));
    assert_eq!(reported, without_duplicate, "speculative pages must not be counted twice");
}
""".replace("EXPRESSION", expression)
folder = ROOT / "docs/audits/AUD-004-evidence"
rust = folder / "macos-memory-expression.rs"
binary = folder / "macos-memory-expression"
rust.write_text(fixture)
subprocess.run(["rustc", "--edition=2021", str(rust), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True)
