//! Worker threads that a system may refuse, as under a limit on processes or on the tasks of a
//! control group: the work goes on with the threads the system gives, never stopping the program
//! (AUD-024-FUN002). Native builds only; a WebAssembly build has no threads here.

use std::thread::{self, Scope};

/// Starts up to `count` threads in `scope`, each running `work`, and gives how many the system
/// started; the first thread it refuses ends the starting.
pub(crate) fn start_scoped<'scope, F>(
    scope: &'scope Scope<'scope, '_>,
    count: usize,
    work: &'scope F,
) -> usize
where
    F: Fn() + Sync,
{
    (0..count)
        .take_while(|_| thread::Builder::new().spawn_scoped(scope, work).is_ok())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn every_started_thread_runs_the_work() {
        let ran = AtomicUsize::new(0);
        let work = || {
            ran.fetch_add(1, Ordering::Relaxed);
        };
        let started = thread::scope(|scope| start_scoped(scope, 3, &work));
        assert_eq!(started, 3);
        assert_eq!(ran.load(Ordering::Relaxed), 3);
        assert_eq!(thread::scope(|scope| start_scoped(scope, 0, &work)), 0);
    }
}
