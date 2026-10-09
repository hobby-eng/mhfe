//! The checked draw of a new phrase on several threads at once, for a native program:
//! [`PhraseDraw::draw_on_every_core`](super::PhraseDraw::draw_on_every_core). A page runs the same
//! draws in workers of its own instead.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;

use zeroize::Zeroizing;

use super::{PhraseDraw, DRAW_REPORT_INTERVAL, NEW_ENTROPY_BYTES};
use crate::random::{check_source, RandomSource};
use crate::MhfeError;

/// A drawn entropy, wiped when dropped.
type Entropy = Zeroizing<[u8; NEW_ENTROPY_BYTES]>;

/// What the threads of one draw share: the first ending, a passing entropy or an error, and the
/// count of the draws that found nothing, with the callback that hears it.
pub(super) struct ThreadedDraw<'a> {
    draw: &'a PhraseDraw,
    /// Set by the first thread that ends the draw; the others stop before their next draw.
    ended: AtomicBool,
    /// What that thread ended the draw with.
    ending: Mutex<Option<Result<Entropy, MhfeError>>>,
    /// Draws that found nothing, over all threads.
    draws: AtomicU64,
    reports: Mutex<Reports<'a>>,
}

/// The callback that hears the count of draws, and the last count it heard.
struct Reports<'a> {
    on_draws: super::SharedDrawReport<'a>,
    heard: u64,
}

impl<'a> ThreadedDraw<'a> {
    pub(super) fn new(draw: &'a PhraseDraw, on_draws: super::SharedDrawReport<'a>) -> Self {
        Self {
            draw,
            ended: AtomicBool::new(false),
            ending: Mutex::new(None),
            draws: AtomicU64::new(0),
            reports: Mutex::new(Reports { on_draws, heard: 0 }),
        }
    }

    /// Draws on `threads` threads, the calling one among them, each with its own source from
    /// `new_source`, until one of them ends the draw: the passing entropy, or the error that ended
    /// it. Where the system gives fewer threads, as under a limit on processes, the draw goes on
    /// with those it gave, at least the calling one, rather than stopping the program.
    pub(super) fn run<S, F>(self, threads: usize, new_source: &F) -> Result<Entropy, MhfeError>
    where
        S: RandomSource,
        F: Fn() -> S + Sync,
    {
        thread::scope(|scope| {
            for _ in 1..threads {
                let started =
                    thread::Builder::new().spawn_scoped(scope, || self.work(&mut new_source()));
                if started.is_err() {
                    break;
                }
            }
            self.work(&mut new_source());
        });
        // Nothing panics while the lock is held, so it is never poisoned; this only avoids an
        // unwrap.
        self.ending
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .unwrap_or_else(|| Err(MhfeError::Internal("no phrase was drawn".to_owned())))
    }

    /// One thread's part: what it finds ends the draw, unless another thread ended it first.
    fn work(&self, source: &mut dyn RandomSource) {
        if let Some(ending) = self.search(source) {
            self.end(ending);
        }
    }

    /// Probes the source, then draws one entropy at a time: the passing entropy or an error, or
    /// `None` when another thread ended the draw first.
    fn search(&self, source: &mut dyn RandomSource) -> Option<Result<Entropy, MhfeError>> {
        if let Err(error) = check_source(source) {
            return Some(Err(error));
        }
        while !self.ended.load(Ordering::Relaxed) {
            match self.draw.try_draws(source, 1) {
                Ok(None) => {
                    if let Err(error) = self.count_draw() {
                        return Some(Err(error));
                    }
                }
                Ok(Some(entropy)) => return Some(Ok(entropy)),
                Err(error) => return Some(Err(error)),
            }
        }
        None
    }

    /// Counts a draw that found nothing; every [`DRAW_REPORT_INTERVAL`] draws the callback hears
    /// the count, and an error it returns ends the draw.
    fn count_draw(&self) -> Result<(), MhfeError> {
        let draws = self.draws.fetch_add(1, Ordering::Relaxed) + 1;
        if !draws.is_multiple_of(DRAW_REPORT_INTERVAL) {
            return Ok(());
        }
        let mut reports = self.reports.lock().unwrap_or_else(PoisonError::into_inner);
        // Two threads may come here in either order: the callback hears only a count larger than
        // the last it heard.
        if draws > reports.heard {
            reports.heard = draws;
            (reports.on_draws)(draws)?;
        }
        Ok(())
    }

    /// Keeps the first ending. A later one, from a thread that ended its own draw at the same
    /// time, is dropped, and an entropy in it wiped.
    fn end(&self, ending: Result<Entropy, MhfeError>) {
        if !self.ended.swap(true, Ordering::SeqCst) {
            *self.ending.lock().unwrap_or_else(PoisonError::into_inner) = Some(ending);
        }
    }
}
