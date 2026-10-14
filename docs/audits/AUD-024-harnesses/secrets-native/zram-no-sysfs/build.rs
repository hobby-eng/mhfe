//! Takes mhfe's src/bin/mhfe/protect/swap.rs as it is in the repository, without its two `//!`
//! header lines (inner doc comments, which `include!` cannot take), and adds one public accessor of
//! its private `unprotected_swap_under`. The code under test is otherwise the repository's, byte
//! for byte.
use std::path::Path;

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let source = Path::new(&manifest).join("../../../../../src/bin/mhfe/protect/swap.rs");
    println!("cargo:rerun-if-changed={}", source.display());
    let text = std::fs::read_to_string(&source).expect("the repository's swap.rs");
    let body: Vec<&str> = text.lines().skip(2).collect();
    let copy = format!(
        "{}\n\n/// Harness accessor (not in the repository).\npub fn probe_under(root: &Path) -> SwapInventory {{\n    unprotected_swap_under(root)\n}}\n",
        body.join("\n")
    );
    let out = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR");
    std::fs::write(Path::new(&out).join("swap_copy.rs"), copy).expect("OUT_DIR is writable");
}
