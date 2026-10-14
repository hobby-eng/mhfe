//! AUD-024 secrets-native harness: the answer labels of the check-word review of a password, by
//! the criterion of the repository's own regression test of AUD-023-SEC001 (an allocator that
//! counts blocks freed while they still hold a watched word, src/bin/mhfe/typed_line.rs:497-566).
//!
//! The steps below are the tool's at commit b6fca69, each copied with its format string:
//! - check_word.rs:196-203, Action::answer for a replacement: `Answer::new(format!("Word {}: {}
//!   instead of {}", ...), "")`, whose label choice.rs:66-71 moves into a Zeroizing<String>;
//! - choice.rs:393-411, draw_entry_rows for the highlighted answer:
//!   `Zeroizing::new(paint(STRONG, label))`, then `Zeroizing::new(format!("{marker} {number}  {}",
//!   *shown_label))`, with style.rs:67-69 `paint(style, text) = format!("{style}{text}{style:#}")`
//!   and the styles of style.rs:34-39.
//! The final buffers are wiped (Zeroizing); the probe counts the intermediate blocks that the
//! growth of each String frees unwiped. Public test words only: "zookeeper", typed "zookeepr".
//! Exits 1 when any step frees such a block (the defect of AUD-024), 0 otherwise.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use anstyle::{AnsiColor, Style};
use zeroize::Zeroizing;

const WATCHED: &[u8] = b"zookeeper";
static UNWIPED: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static WATCHING: Cell<bool> = const { Cell::new(false) };
}

struct Inspecting;

// SAFETY: every call goes to the system allocator unchanged; dealloc reads the block first.
unsafe impl GlobalAlloc for Inspecting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        if WATCHING.with(Cell::get) {
            let bytes = unsafe { std::slice::from_raw_parts(block, layout.size()) };
            if bytes.windows(WATCHED.len()).any(|window| window == WATCHED) {
                UNWIPED.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(block, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Inspecting = Inspecting;

// style.rs:34-39
const ACCENT: Style = AnsiColor::Cyan.on_default();
const STRONG: Style = Style::new().bold();
const MUTED: Style = AnsiColor::BrightBlack.on_default();

// style.rs:67-69
fn paint(style: Style, text: impl std::fmt::Display) -> String {
    format!("{style}{text}{style:#}")
}

static TOTAL: AtomicUsize = AtomicUsize::new(0);

fn counted(step: &str, run: impl FnOnce()) {
    WATCHING.with(|watching| watching.set(true));
    let before = UNWIPED.load(Ordering::SeqCst);
    run();
    let freed = UNWIPED.load(Ordering::SeqCst) - before;
    WATCHING.with(|watching| watching.set(false));
    TOTAL.fetch_add(freed, Ordering::SeqCst);
    println!("{step}: {freed} block(s) freed unwiped holding \"zookeeper\"");
}

fn main() {
    let (position, word, typed) = (6, "zookeeper", "zookeepr");
    let mut label = Zeroizing::new(String::new());
    counted("check_word.rs:196 label format!", || {
        // Answer::new(label.into()): the String is moved into a Zeroizing<String>.
        label = Zeroizing::new(format!("Word {}: {} instead of {}", position, word, typed));
    });
    let mut shown_label = Zeroizing::new(String::new());
    counted("choice.rs:394 paint(STRONG, label)", || {
        shown_label = Zeroizing::new(paint(STRONG, label.as_str()));
    });
    let marker = paint(ACCENT, "›");
    let number = paint(MUTED, 1);
    counted("choice.rs:401-402 the answer's line, format!", || {
        let line = Zeroizing::new(format!("{marker} {number}  {}", *shown_label));
        drop(line);
    });
    counted("control: the wiped label drawn dropped", || drop(shown_label));
    counted("control: the wiped final label dropped", || drop(label));
    let total = TOTAL.load(Ordering::SeqCst);
    if total > 0 {
        println!("FAIL: {total} block(s) holding a word of the password freed without a wipe");
    } else {
        println!("PASS: no block holding a word of the password freed without a wipe");
    }
    std::process::exit(i32::from(total > 0));
}
