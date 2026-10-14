//! AUD-024 guide-lib-core: the public `mhfe::memory` API lets a caller build a `LockedText` from a
//! guard of another buffer (`LockedText::from_locked` with `LockedPages::of_vec`). The text then
//! reports `is_locked()` while the kernel holds none of its own pages locked. Exits 1 when that
//! happens, 0 when the library refuses it or reports it correctly. Linux only (reads
//! /proc/self/smaps). Public test text only.
use mhfe::memory::{LockedPages, LockedText};
use zeroize::Zeroizing;

/// Whether the mapping that holds `address` is locked: its VmFlags in /proc/self/smaps hold "lo".
fn kernel_keeps_locked(address: usize) -> bool {
    let smaps = std::fs::read_to_string("/proc/self/smaps").expect("/proc/self/smaps");
    let mut inside = false;
    for line in smaps.lines() {
        let range = line.split_once(' ').map_or(line, |(range, _)| range);
        if let Some((start, end)) = range.split_once('-') {
            if let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) {
                inside = (start..end).contains(&address);
                continue;
            }
        }
        if let (true, Some(flags)) = (inside, line.strip_prefix("VmFlags:")) {
            return flags.split_whitespace().any(|flag| flag == "lo");
        }
    }
    false
}

fn main() {
    const PAGE: usize = 4096;
    // The text in an ordinary buffer of three pages: nothing locks it.
    let mut text = Zeroizing::new(String::with_capacity(3 * PAGE));
    text.push_str("public test password");
    let text_page = (text.as_ptr() as usize).next_multiple_of(PAGE);
    // A guard that locks another buffer.
    let other: Vec<u8> = Vec::with_capacity(64);
    let guard = LockedPages::of_vec(&other);
    println!("guard of the other buffer is_locked() = {}", guard.is_locked());
    let locked = LockedText::from_locked(text, guard);
    let reported = locked.is_locked();
    let actual = kernel_keeps_locked(text_page);
    println!("LockedText::is_locked() = {reported}");
    println!("kernel keeps a page of the text's own buffer locked = {actual}");
    if reported && !actual {
        println!("FAIL: the LockedText reports a lock its buffer does not have");
        std::process::exit(1);
    }
    println!("OK");
}
