//! The checks at start. Before a command that handles a secret reads anything, every part of the
//! program is compared with its known answers (`mhfe::self_check`, at its startup tier) and the
//! protections of the process are read back: a broken build, a faulty processor or memory, or a
//! damaged table then shows before a secret is typed, not in a container that cannot be recovered.
//! The checks take a few tens of milliseconds and a few MiB, run offline with public test vectors
//! only, and show nothing when they pass. A failure stops the tool with exit code 1 and names the
//! part. `mhfe self-test` runs the same checks and the slower ones of its full tier.

use std::sync::{Mutex, MutexGuard, Once, PoisonError};

use mhfe::random::RandomSource;
use mhfe::self_check::{sets, ComponentResult, SelfCheck, SelfCheckReport, Tier};

use crate::exit::{Failure, INTERNAL_ERROR};
use crate::hidden_input::{self, HiddenInputCheck};
use crate::protect::{self, CoreDumpCheck, IsolationCheck};
use crate::{flow, readme, style};

/// Which checks a command runs at its start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checks {
    /// Every part: for every command that reads a secret, and for the menu once.
    EveryPart,
    /// The cipher's hashes alone, SHA-256 among them: for `mhfe serve`, which handles no secret
    /// but compares a page with its SHA-256 before serving it.
    Hashes,
    /// None, for a command that runs every check itself or none that it relies on.
    Nothing,
}

/// Every check of the tool, in the order a report lists them: the library's parts with the native
/// Argon2 engine, then the process's own protections. `random` is the generator new passwords and
/// phrases are drawn from, which only the full self-test tries; at start only scripted sources are
/// used, so that no draw can wait for the system's generator.
pub fn every_part<'a>(random: Option<&'a mut dyn RandomSource>) -> SelfCheck<'a> {
    sets::native(random)
        .with(CoreDumpCheck)
        .with(IsolationCheck)
        .with(HiddenInputCheck)
}

/// Runs `checks` at the startup tier; on a failure, says which part failed and returns the exit
/// code to stop with, after the message has been shown. A part that only warns, such as memory
/// that cannot be locked, is stated where it matters, in the summary of the settings.
pub fn check(checks: Checks) -> Result<(), Failure> {
    let mut set = match checks {
        Checks::EveryPart => every_part(None),
        Checks::Hashes => sets::hashes(),
        Checks::Nothing => return Ok(()),
    };
    let report = run_named(&mut set, Tier::Startup, AT_START, &mut |_| {}, &mut |_| {});
    match report.first_failure() {
        None => Ok(()),
        Some(failed) => {
            style::error_wrapped(&failure_text(failed));
            style::more(readme::SELF_TEST);
            Err(Failure::shown(INTERNAL_ERROR))
        }
    }
}

/// How a failure at start begins; the self-test a person runs says "Self-test failed".
const AT_START: &str = "Self-test at start failed";

/// The message of a part that failed at start. Core dumps that stay on are not a fault of the
/// program but of the system it runs on, so they are named as such.
fn failure_text(failed: &ComponentResult) -> String {
    if failed.id() == protect::CORE_DUMPS_ID {
        return "Core dumps could not be turned off.".to_owned();
    }
    let detail = failed.outcome().detail().unwrap_or("it failed");
    format!(
        "{}.",
        mhfe::self_check::failure_message(AT_START, failed.label(), detail)
    )
}

/// Runs `set` at `tier`, with `on_start` told the label of every part as it starts and `on_result`
/// every outcome. While a part runs, its label is kept for the panic hook, so that a part that
/// stops the program, as a damaged table could, is named: "<what>: <label>: the program stopped."
pub fn run_named(
    set: &mut SelfCheck<'_>,
    tier: Tier,
    what: &'static str,
    on_start: &mut dyn FnMut(&'static str),
    on_result: &mut dyn FnMut(&ComponentResult),
) -> SelfCheckReport {
    install_panic_hook();
    let report = set.run(
        tier,
        &mut |_, label| {
            set_running(Some(Running { what, label }));
            on_start(label);
        },
        &mut |result| {
            set_running(None);
            on_result(result);
        },
    );
    set_running(None);
    report
}

/// The part that is running, for the panic hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Running {
    /// How the message begins: [`AT_START`] or the full self-test's.
    what: &'static str,
    label: &'static str,
}

static RUNNING: Mutex<Option<Running>> = Mutex::new(None);

/// Nothing panics while the lock is held, so it is never poisoned; this only avoids an unwrap.
fn running() -> MutexGuard<'static, Option<Running>> {
    RUNNING.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Held by every test that runs checks, so that only one names its running part at a time.
#[cfg(test)]
pub fn one_test_at_a_time() -> MutexGuard<'static, ()> {
    static TESTS: Mutex<()> = Mutex::new(());
    TESTS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn set_running(part: Option<Running>) {
    *running() = part;
}

/// What the panic hook says when `part` stopped the program.
fn stopped_text(part: Running) -> String {
    format!("{}: {}: the program stopped.", part.what, part.label)
}

/// Installs, once, a panic hook that names the part a check was running when the program panicked,
/// leaves the private screen with the summary so far and the terminal as it found it, and ends
/// the tool with exit code 1 instead of an abort. Outside the checks it leaves panics to the hook
/// before it.
fn install_panic_hook() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let before = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // try_lock: the panic may have come while the lock was held.
            let part = RUNNING.try_lock().ok().and_then(|guard| *guard);
            let Some(part) = part else {
                before(info);
                return;
            };
            flow::end_at_exit();
            crate::terminal::leave_steps();
            anstream::eprintln!();
            style::error_wrapped(&stopped_text(part));
            style::more(readme::SELF_TEST);
            // A test goes on unwinding; the tool ends with the exit code of an internal error.
            if !cfg!(test) {
                hidden_input::restore_and_exit(exit_after_panic);
            }
        }));
    });
}

fn exit_after_panic() -> ! {
    std::process::exit(INTERNAL_ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mhfe::self_check::{ComponentCheck, ComponentOutcome};

    /// A part with a fixed outcome.
    struct Fixed(&'static str, ComponentOutcome);

    impl ComponentCheck for Fixed {
        fn id(&self) -> &'static str {
            self.0
        }

        fn label(&self) -> &'static str {
            "Fixed part"
        }

        fn run(&mut self, _: Tier) -> ComponentOutcome {
            self.1.clone()
        }
    }

    /// The tool's set holds every part of the library's native set, and its own three, once.
    #[test]
    fn every_part_adds_the_process_checks_to_the_library_set() {
        let library = sets::native(None).ids();
        let ids = every_part(None).ids();
        assert_eq!(ids[..library.len()], library[..]);
        assert_eq!(
            ids[library.len()..],
            [
                protect::CORE_DUMPS_ID,
                protect::ISOLATION_ID,
                hidden_input::HIDDEN_INPUT_ID
            ]
        );
        assert_eq!(
            library.len(),
            26,
            "the plan's 22 parts of the library, the address search, the search for missing words, \
             the chosen word of a new phrase and the word hints"
        );
    }

    /// The checks at start pass on this computer, as they must before any secret command, and
    /// leave out the parts of the full self-test only.
    #[test]
    fn every_part_passes_at_start() {
        let _alone = one_test_at_a_time();
        protect::harden_process();
        let mut set = every_part(None);
        let mut seen = Vec::new();
        let report = run_named(
            &mut set,
            Tier::Startup,
            AT_START,
            &mut |_| {},
            &mut |result| seen.push(result.id()),
        );
        assert!(report.passed(), "{:?}", report.first_failure());
        assert!(!seen.contains(&"argon2-sizes"));
        assert!(!seen.contains(&hidden_input::HIDDEN_INPUT_ID));
        assert!(seen.contains(&"argon2") && seen.contains(&protect::CORE_DUMPS_ID));
        assert_eq!(
            *running(),
            None,
            "no part is named once the checks have ended"
        );
        assert!(check(Checks::Hashes).is_ok());
        assert!(check(Checks::Nothing).is_ok());
    }

    #[test]
    fn a_failure_names_the_part_and_what_differed() {
        let _alone = one_test_at_a_time();
        let mut set = SelfCheck::new()
            .with(Fixed("passing", ComponentOutcome::Passed))
            .with(Fixed(
                "cipher-rounds",
                ComponentOutcome::Failed("vector 4 of 10 gives another container".to_owned()),
            ));
        let report = run_named(&mut set, Tier::Startup, AT_START, &mut |_| {}, &mut |_| {});
        let failed = report.first_failure().unwrap();
        assert_eq!(
            failure_text(failed),
            "Self-test at start failed: Fixed part: vector 4 of 10 gives another container. Do \
             not use this program on this computer."
        );
        let mut core_dumps = SelfCheck::new().with(Fixed(
            protect::CORE_DUMPS_ID,
            ComponentOutcome::Failed("the kernel still allows them".to_owned()),
        ));
        let report = core_dumps.run_quietly(Tier::Startup);
        assert_eq!(
            failure_text(report.first_failure().unwrap()),
            "Core dumps could not be turned off."
        );
    }

    /// While a part runs, the panic hook knows its label; afterwards it knows none.
    #[test]
    fn the_running_part_is_named_for_the_panic_hook() {
        struct Watching;

        impl ComponentCheck for Watching {
            fn id(&self) -> &'static str {
                "watching"
            }

            fn label(&self) -> &'static str {
                "Watching part"
            }

            fn run(&mut self, _: Tier) -> ComponentOutcome {
                match *running() {
                    Some(part) if part.label == "Watching part" => ComponentOutcome::Passed,
                    other => ComponentOutcome::Failed(format!("{other:?}")),
                }
            }
        }

        let _alone = one_test_at_a_time();
        let mut set = SelfCheck::new().with(Watching);
        let mut started = Vec::new();
        let report = run_named(
            &mut set,
            Tier::Full,
            "Self-test failed",
            &mut |label| started.push(label),
            &mut |_| {},
        );
        assert_eq!(started, ["Watching part"]);
        assert!(report.passed(), "{:?}", report.first_failure());
        assert_eq!(
            stopped_text(Running {
                what: AT_START,
                label: "Repair words (MHFE-REPAIR-1)"
            }),
            "Self-test at start failed: Repair words (MHFE-REPAIR-1): the program stopped."
        );
    }
}
