#!/usr/bin/env python3
"""AUD-024 harness: what the swap warning says in a build for a system other than Linux.

It copies, unchanged, `unprotected_swap` from src/bin/mhfe/protect/swap.rs, the `SwapArea` and
`SwapInventory` types from src/bin/mhfe/protect.rs and `swap_warning` from src/bin/mhfe/settings.rs
into one Rust file. `cfg!(target_os = "linux")` is replaced by `false`, the value that macro takes
in the Windows and macOS release builds; nothing else is changed. `style::escaped` is stubbed (it
only escapes names). It then compiles and runs that file and prints the inventory and the warning.

Exit 0: the non-Linux build gives a warning (or an unknown state that warns). Exit 1: it gives no
warning at all, though nothing was inspected. Exit 2: the sources no longer have the expected shape.

    python3 docs/audits/AUD-024-harnesses/verify-repro/non-linux-swap/non_linux_swap.py <scratch>
"""

import subprocess
import sys
from pathlib import Path


def block(text: str, start: str, path: str) -> str:
    """The item that begins with `start`, to the first closing brace at column 0."""
    begin = text.find(start)
    if begin < 0:
        sys.exit(f"shape changed: {start!r} not found in {path}")
    end = text.find("\n}\n", begin)
    if end < 0:
        sys.exit(f"shape changed: no end of {start!r} in {path}")
    return text[begin : end + 3]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    scratch = Path(sys.argv[1])
    scratch.mkdir(parents=True, exist_ok=True)
    swap = Path("src/bin/mhfe/protect/swap.rs").read_text()
    protect = Path("src/bin/mhfe/protect.rs").read_text()
    settings = Path("src/bin/mhfe/settings.rs").read_text()

    unprotected = block(swap, "pub fn unprotected_swap() -> SwapInventory {", "swap.rs")
    if unprotected.count('cfg!(target_os = "linux")') != 1:
        print("shape changed: unprotected_swap no longer tests cfg!(target_os = \"linux\")")
        return 2
    unprotected = unprotected.replace('cfg!(target_os = "linux")', "false")
    area = block(protect, "pub struct SwapArea {", "protect.rs")
    inventory = block(protect, "pub enum SwapInventory {", "protect.rs")
    warning = block(settings, "fn swap_warning(", "settings.rs")

    program = f"""#![allow(dead_code)]
mod style {{
    pub fn escaped(text: &str) -> String {{ text.to_owned() }}
}}
mod protect {{
    use std::path::Path;
    #[derive(Debug, PartialEq, Eq)]
    {area}
    #[derive(Debug, PartialEq, Eq)]
    {inventory}
    // The Linux branch is not taken in a non-Linux build.
    fn unprotected_swap_under(_: &Path) -> SwapInventory {{ unreachable!() }}
    {unprotected}
}}
{warning}
fn main() {{
    // Control: the harness sees a warning where the code gives one.
    let control = swap_warning(&protect::SwapInventory::Unavailable);
    println!("control (Unavailable): {{control:?}}");
    assert!(control.is_some());
    let inventory = protect::unprotected_swap();
    let warning = swap_warning(&inventory);
    println!("non-Linux build: inventory {{inventory:?}}, warning {{warning:?}}");
    std::process::exit(if warning.is_some() {{ 0 }} else {{ 1 }});
}}
"""
    source = scratch / "non_linux_swap.rs"
    source.write_text(program)
    binary = scratch / "non_linux_swap"
    build = subprocess.run(
        ["rustc", "--edition", "2021", "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        print(build.stderr)
        print("shape changed: the extracted code does not compile")
        return 2
    run = subprocess.run([str(binary)], capture_output=True, text=True)
    print(run.stdout, end="")
    print(run.stderr, end="", file=sys.stderr)
    if run.returncode == 0:
        print("PASS: a non-Linux build warns or reports the swap as unknown")
        return 0
    if run.returncode == 1:
        print("FAIL: a non-Linux build reports an inspected, empty swap inventory and warns nothing")
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
