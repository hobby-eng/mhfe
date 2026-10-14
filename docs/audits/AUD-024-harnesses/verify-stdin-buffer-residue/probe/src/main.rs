//! AUD-024 verifier probe. Reads one line from standard input in one of three ways, wipes the
//! program's own copy with volatile writes and keeps it allocated (so that a freed chunk cannot be
//! mistaken for std's), then scans the heap and anonymous mappings through /proc/self/mem for the
//! text whose reverse is given, printing the address of each copy and whether it lies inside the
//! standard library's stdin buffer (found through fill_buf before the line is read).
//!   bytes      one byte at a time from io::stdin().lock(), as hidden_input.rs edit_line does
//!   line       take(8192).read_line into a String reserved at 8192, as terminal.rs read_bounded_line
//!   descriptor one byte at a time from file descriptor 0, past std's buffer (control)
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn copies(reversed: &[u8]) -> Vec<u64> {
    let maps = BufReader::new(File::open("/proc/self/maps").unwrap());
    let lines: Vec<String> = maps.lines().map(Result::unwrap).collect();
    let mut memory = File::open("/proc/self/mem").unwrap();
    let length = reversed.len();
    let mut found = Vec::new();
    let mut chunk = vec![0u8; 0]; // reserved below; never holds the text in the clear
    chunk.reserve_exact(4096 + 256);
    chunk.resize(4096 + 256, 0);
    let chunk_at = chunk.as_ptr() as u64;
    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let name = fields.get(5).copied().unwrap_or("");
        if !fields[1].starts_with("rw") || !(name.is_empty() || name == "[heap]") {
            continue;
        }
        let (start, end) = fields[0].split_once('-').unwrap();
        let (start, end) = (u64::from_str_radix(start, 16).unwrap(), u64::from_str_radix(end, 16).unwrap());
        let mut at = start;
        while at < end {
            let want = ((end - at) as usize).min(4096 + length);
            if memory.seek(SeekFrom::Start(at)).is_err() || memory.read_exact(&mut chunk[..want]).is_err() {
                at += 4096;
                continue;
            }
            for offset in 0..want.min(4096).min(want.saturating_sub(length - 1)) {
                if (0..length).all(|k| chunk[offset + k] == reversed[length - 1 - k]) {
                    let address = at + offset as u64;
                    // The scan's own chunk is excluded: it is a copy the scan made.
                    if address < chunk_at || address >= chunk_at + chunk.len() as u64 {
                        found.push(address);
                    }
                }
            }
            at += 4096;
        }
        wipe(&mut chunk);
    }
    found
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let mode = arguments[1].clone();
    let reversed = arguments[2].as_bytes().to_vec();
    let tail_reversed = arguments.get(3).map(|tail| tail.as_bytes().to_vec());
    let mut std_buffer: Option<u64> = None;
    let mut line: Vec<u8> = Vec::with_capacity(8192);
    match mode.as_str() {
        "bytes" => {
            let mut lock = std::io::stdin().lock();
            std_buffer = Some(lock.fill_buf().unwrap().as_ptr() as u64);
            let mut byte = [0u8; 1];
            while lock.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' && byte[0] != b'\r' {
                line.push(byte[0]);
            }
            wipe(&mut byte);
        }
        "line" => {
            let mut lock = std::io::stdin().lock();
            std_buffer = Some(lock.fill_buf().unwrap().as_ptr() as u64);
            let mut text = String::with_capacity(8192);
            (&mut lock).take(8192).read_line(&mut text).unwrap();
            let mut bytes = text.into_bytes();
            bytes.truncate(bytes.len().saturating_sub(1));
            line = bytes;
        }
        _ => {
            use std::os::fd::FromRawFd;
            let mut file = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(0) });
            let mut byte = [0u8; 1];
            while file.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' && byte[0] != b'\r' {
                line.push(byte[0]);
            }
            wipe(&mut byte);
        }
    }
    let read = line.len();
    let own = line.as_ptr() as u64;
    // The program wipes its own copy, as LockedText does when dropped, and keeps it allocated.
    let capacity = line.capacity();
    unsafe { line.set_len(capacity) };
    wipe(&mut line);
    let found = copies(&reversed);
    let in_std = |address: &u64| std_buffer.is_some_and(|start| *address >= start && *address < start + 8192);
    println!(
        "{mode}: read {read} bytes into its own buffer at {own:#x}, wiped it (kept allocated); std stdin buffer at {}",
        std_buffer.map_or("not used".to_owned(), |start| format!("{start:#x}"))
    );
    println!(
        "  whole-text copies: {} {:?}; inside std's buffer: {}",
        found.len(),
        found.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>(),
        found.iter().filter(|a| in_std(a)).count()
    );
    if let Some(tail) = tail_reversed {
        let tails = copies(&tail);
        println!(
            "  tail copies: {} {:?}; inside std's buffer: {}",
            tails.len(),
            tails.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>(),
            tails.iter().filter(|a| in_std(a)).count()
        );
    }
    std::hint::black_box(&line);
}
