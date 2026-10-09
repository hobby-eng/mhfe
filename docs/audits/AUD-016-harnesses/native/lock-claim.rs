//! AUD-016: compare the production locking check with the real CLI input buffer size.

use mhfe::memory::{LockProbe, LockedText};
use mhfe::self_check::{ComponentCheck, Tier};

// The native CLI's terminal::LINE_CAPACITY. This audit-only witness covers that production
// allocation size; it contains no alternate allocator or copy of the locking implementation.
const CLI_LINE_CAPACITY: usize = 8192;

fn main() {
    let probe = LockProbe.run(Tier::Startup);
    let line = LockedText::build::<()>(CLI_LINE_CAPACITY, |line| {
        line.push_str("AUD016 public synthetic input");
        Ok(())
    })
    .unwrap();
    println!(
        "{{\"probeOutcome\":\"{}\",\"typedBufferLocked\":{},\"capacity\":{}}}",
        probe.name(),
        line.is_locked(),
        line.capacity()
    );
    if probe.name() == "passed" && !line.is_locked() {
        eprintln!("the production check passes while the CLI-sized buffer is not locked");
        std::process::exit(1);
    }
}
