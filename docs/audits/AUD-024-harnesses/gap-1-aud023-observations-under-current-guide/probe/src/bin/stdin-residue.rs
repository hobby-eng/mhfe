//! AUD-024 probe: a line read from standard input the way mhfe reads a hidden or typed line
//! (src/bin/mhfe/hidden_input.rs edit_line: one byte at a time from io::stdin().lock()), then
//! wiped in the program's own buffer. Is a copy left in the standard library's stdin buffer? The
//! control reads the same line straight from the file descriptor, past std's buffer.
//! The searched text is given reversed on the command line, so that the probe holds no copy of it.
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

fn read_line_like_mhfe() -> Vec<u8> {
    let mut lock = std::io::stdin().lock();
    let mut line = Vec::with_capacity(8192);
    let mut byte = [0u8; 1];
    while lock.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
        line.push(byte[0]);
    }
    line
}

fn read_line_from_descriptor() -> Vec<u8> {
    use std::os::fd::FromRawFd;
    // Fd 0 itself, without std's buffer; ManuallyDrop keeps it open.
    let mut file = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(0) });
    let mut line = Vec::with_capacity(8192);
    let mut byte = [0u8; 1];
    while file.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
        line.push(byte[0]);
    }
    line
}

/// Copies of the text whose reverse is `reversed` in the heap and anonymous mappings (not the
/// stack, where the scan's own chunk lives), read through /proc/self/mem in chunks on the stack.
fn copies(reversed: &[u8]) -> usize {
    let maps = BufReader::new(File::open("/proc/self/maps").unwrap());
    let mut memory = File::open("/proc/self/mem").unwrap();
    let length = reversed.len();
    let mut found = 0;
    for line in maps.lines().map(Result::unwrap) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let name = fields.get(5).copied().unwrap_or("");
        if !fields[1].starts_with("rw") || !(name.is_empty() || name == "[heap]") {
            continue;
        }
        let (start, end) = fields[0].split_once('-').unwrap();
        let (start, end) = (u64::from_str_radix(start, 16).unwrap(), u64::from_str_radix(end, 16).unwrap());
        let mut chunk = [0u8; 4096 + 64];
        let mut at = start;
        while at < end {
            let want = ((end - at) as usize).min(4096 + length);
            if memory.seek(SeekFrom::Start(at)).is_err() || memory.read_exact(&mut chunk[..want]).is_err() {
                at += 4096;
                continue;
            }
            for offset in 0..want.min(4096).min(want.saturating_sub(length - 1)) {
                if (0..length).all(|k| chunk[offset + k] == reversed[length - 1 - k]) {
                    found += 1;
                }
            }
            at += 4096;
        }
        chunk.fill(0);
    }
    found
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let mode = arguments[1].as_str();
    let reversed = arguments[2].as_bytes().to_vec();
    let mut line = match mode {
        "std" => read_line_like_mhfe(),
        _ => read_line_from_descriptor(),
    };
    let read = line.len();
    // The program wipes its own copy, as mhfe's LockedText does when dropped.
    line.iter_mut().for_each(|byte| *byte = 0);
    drop(line);
    println!("{mode}: read {read} bytes, wiped its own copy; copies left in heap and anonymous memory: {}", copies(&reversed));
}
