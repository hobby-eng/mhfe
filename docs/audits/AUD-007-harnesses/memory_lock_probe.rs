use mhfe::memory::LockedPages;
fn locked_kib() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|line| line.starts_with("VmLck:"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}
fn page_locked(address: usize) -> bool {
    let mut selected = false;
    for line in std::fs::read_to_string("/proc/self/smaps").unwrap().lines() {
        let token = line.split_whitespace().next().unwrap_or("");
        if let Some((left, right)) = token.split_once('-') {
            if let (Ok(left), Ok(right)) = (
                usize::from_str_radix(left, 16),
                usize::from_str_radix(right, 16),
            ) {
                selected = left <= address && address < right;
            }
        }
        if selected && line.starts_with("VmFlags:") {
            return line.split_whitespace().any(|flag| flag == "lo");
        }
    }
    panic!("the synthetic buffer mapping was not found");
}
fn main() {
    let buffer = vec![0u8; 8192];
    let before = locked_kib();
    let first = LockedPages::of_vec(&buffer);
    let after_first = locked_kib();
    let second = LockedPages::of_vec(&buffer);
    let after_second = locked_kib();
    assert!(first.is_locked() && second.is_locked());
    drop(first);
    let after_first_drop = locked_kib();
    println!("before_kib={before} after_first_kib={after_first} after_second_kib={after_second} after_first_drop_kib={after_first_drop} remaining_guard_reports_locked={}", second.is_locked());
    assert!(after_first > before);
    assert_eq!(after_second, after_first);
    assert_eq!(after_first_drop, before);
    assert!(second.is_locked());
    let page_size = 4096usize;
    let mut passwords: Vec<Option<mhfe::Password>> = (0..64)
        .map(|_| Some(mhfe::Password::new("public test password alpha").unwrap()))
        .collect();
    let mut shared = None;
    for first in 0..passwords.len() {
        for other in first + 1..passwords.len() {
            let left = passwords[first].as_ref().unwrap().as_bytes().as_ptr() as usize;
            let right = passwords[other].as_ref().unwrap().as_bytes().as_ptr() as usize;
            if left / page_size == right / page_size {
                shared = Some((first, other, left));
                break;
            }
        }
        if shared.is_some() {
            break;
        }
    }
    let (first, other, pointer) =
        shared.expect("this allocator placed no two live Password values on the same page");
    assert!(page_locked(pointer));
    drop(passwords[other].take());
    let remaining_password_locked = page_locked(pointer);
    println!("distinct_Password_allocations_share_page=true live_password_page_locked_after_other_password_drop={remaining_password_locked} live_public_password_bytes={}", passwords[first].as_ref().unwrap().as_bytes().len());
    assert!(!remaining_password_locked);
}
