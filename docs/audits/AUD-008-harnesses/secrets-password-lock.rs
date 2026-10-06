//! AUD-008: bounded reproduction of the hidden-wallet password-retention expression.
use zeroize::Zeroizing;

fn page_locked(address: usize) -> bool {
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
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
    // Sixteen synthetic maximum-width passwords: 16 KiB retained, no Argon2 work.
    const COPIES: usize = 16;
    const PASSWORD_BYTES: usize = mhfe::MAX_PASSWORD_BYTES;
    let public_password = "P".repeat(PASSWORD_BYTES);
    let mut used: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut originals_locked = 0;
    for _ in 0..COPIES {
        let password = mhfe::Password::new(&public_password).unwrap();
        originals_locked += usize::from(page_locked(password.as_bytes().as_ptr() as usize));
        // SOURCE_RETENTION_EXPRESSION
    }
    let retained_locked = used
        .iter()
        .filter(|copy| page_locked(copy.as_ptr() as usize))
        .count();
    println!("original_password_pages_locked={originals_locked}/{COPIES}");
    println!("retained_password_copy_pages_locked={retained_locked}/{COPIES}");
    if originals_locked != COPIES {
        println!("BLOCKED: the operating system refused an original password lock");
        std::process::exit(2);
    }
    if retained_locked != COPIES {
        println!("FAIL: retained copies outlive the acquired Password locks");
        std::process::exit(1);
    }
}
