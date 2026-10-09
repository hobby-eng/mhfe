//! The PIM and memory-level options shared by every command that runs MHFE. A person at a
//! terminal who gives neither is asked: the defaults are chosen unless they pick their own.

use anstream::eprintln;
use clap::Args;
use mhfe::engine::{check_can_run, highest_available_level, NativeEngine};
use mhfe::self_check::{ComponentCheck, ComponentOutcome, Tier};
use mhfe::{Mhfe, WorkFactor, ENCRYPTION_ROUNDS, MAX_MEMORY_LEVEL, ROUNDS};

use crate::choice::{self, Answer, Question};
use crate::exit::Failure;
use crate::flow;
use crate::readme;
use crate::style::{self, paint, ACCENT, MUTED, WARNING};
use crate::terminal::Input;

#[derive(Args, Clone, Copy)]
pub struct Settings {
    // Options rather than defaults, so that a command can tell whether the person gave them.
    /// Pass multiplier, 0 to 1023 (default 0)
    #[arg(long, value_name = "N", long_help = pim_help())]
    pub pim: Option<u32>,

    /// Memory level, 0 to 21 (default 0: 2 GiB)
    #[arg(long = "mem", value_name = "LEVEL", long_help = memory_level_help())]
    pub memory_level: Option<u32>,
}

fn pim_help() -> String {
    style::option_help(&[
        &format!("Pass multiplier, {} (default 0).", pim_range()),
        "Every step adds the default work again: PIM 1 doubles the time of the encryption and \
         of every recovery, PIM 9 makes it ten times as long. Each guess of the password costs \
         an attacker the same extra time.",
        "Recovery must use the same PIM. At 0 there is nothing to keep; any other value must \
         be remembered or recorded, like part of the password, because it cannot be found from \
         the container. It may be kept secret.",
    ])
}

fn memory_level_help() -> String {
    style::option_help(&[
        &format!(
            "Memory level, {} (default 0: {}).",
            level_range(),
            memory_text(0)
        ),
        "The memory of every Argon2 call, doubling every two levels; the time grows in \
         proportion to it:",
        &memory_levels(),
        "Recovery must use the same level and needs that much free memory, so choose a level \
         that the computer you will recover on can provide. The browser tools support level 0 \
         only. At 0 there is nothing to keep; any other level must be remembered or recorded \
         like the PIM, and it may be kept secret.",
    ])
}

impl Settings {
    pub fn work_factor(self) -> Result<WorkFactor, Failure> {
        Ok(WorkFactor::new(
            self.pim.unwrap_or(0),
            self.memory_level.unwrap_or(0),
        )?)
    }

    /// Whether the command line gives the PIM or the memory level; then nothing is asked.
    fn given(self) -> bool {
        self.pim.is_some() || self.memory_level.is_some()
    }
}

/// What a command computes, which sets its title and how many rounds it runs.
#[derive(Clone, Copy)]
pub enum Operation {
    /// Twelve rounds forward, then twelve backwards to check that they give the phrase back.
    Encrypt,
    /// Twelve rounds backwards.
    Decrypt,
    /// Twelve rounds backwards, compared with a reference instead of shown.
    Check,
    /// `mhfe rekey`, first the twelve rounds backwards of the old container, confirmed but not
    /// shown...
    Rekey,
    /// ...then the 24 rounds of the new one, as an encryption, under the same title.
    RekeyNew,
    /// `mhfe wallets`: twelve rounds backwards for each wallet another password opens.
    Wallets,
    /// `mhfe new`: a new phrase, then the 24 rounds of an encryption.
    New,
    /// `mhfe repair`: twelve rounds backwards for each candidate of a search for missing words.
    Repair,
}

impl Operation {
    /// The title of the command, at the top of its screen and of its private screen.
    pub const fn title(self) -> &'static str {
        match self {
            Operation::Encrypt => "Encrypt a seed phrase",
            Operation::Decrypt => "Recover a seed phrase",
            Operation::Check => "Rehearse a recovery",
            Operation::Rekey | Operation::RekeyNew => "Change the password",
            Operation::Wallets => "Open hidden wallets",
            Operation::New => "Generate a new wallet",
            Operation::Repair => "Repair a container phrase",
        }
    }
}

/// Announces the command, settles its settings and states them with the memory and the expected
/// time, and refuses at once settings that this computer cannot run. A person at a terminal who
/// gave neither setting is asked first: the defaults, or their own. Nothing secret has been asked
/// yet. The format of the container is shown once it is known: after the choice of an encryption,
/// or from the container's word count.
pub fn choose(
    settings: Settings,
    input: &mut Input,
    operation: Operation,
) -> Result<WorkFactor, Failure> {
    // The new settings of a rekey continue its screen.
    if !matches!(operation, Operation::RekeyNew) {
        style::title(operation.title());
    }
    let defaults = settings.work_factor()?;
    let asked = !settings.given() && input.can_ask_again();
    let work = if asked && ask_for_own(input, operation, defaults)? {
        ask_own(input)?
    } else {
        defaults
    };
    show(work, operation, asked);
    warn_about_swap();
    check_resources(work)?;
    Ok(work)
}

/// Warns, before any secret is typed, when swap could write memory to a disk unencrypted.
fn warn_about_swap() {
    let areas = crate::protect::unprotected_swap();
    if areas.is_empty() {
        return;
    }
    // A device name is the system's text: shown escaped, as every path is.
    let names: Vec<String> = areas
        .iter()
        .map(|area| style::escaped(&area.name))
        .collect();
    let headline = if areas.iter().all(|area| area.unknown) {
        format!(
            "MHFE cannot tell whether swap is encrypted: {}.",
            names.join(", ")
        )
    } else {
        format!(
            "Swap on this computer is not encrypted: {}.",
            names.join(", ")
        )
    };
    // Why it matters, Argon2's work area on a disk for years, is in the README.
    style::warn(
        &headline,
        "Use encrypted swap or none, best a live system from a USB stick.",
    );
    style::more(readme::SAFE_COMPUTER);
    eprintln!();
}

/// Asks whether to keep the defaults; true when the person wants to give their own settings. The
/// question is erased once answered: the settings shown next record the answer.
fn ask_for_own(
    input: &mut Input,
    operation: Operation,
    defaults: WorkFactor,
) -> Result<bool, Failure> {
    let (low, high) = defaults.estimated_seconds();
    let scale = u64::from(rounds_of(operation) / ROUNDS);
    let time = format!("about {}", time_range(low * scale, high * scale));
    let (text, answers) = match operation {
        Operation::Encrypt | Operation::RekeyNew | Operation::New => (
            "Which settings should protect the phrase?",
            [
                Answer::new("PIM 0 and memory level 0 (recommended)", time),
                Answer::new("My own PIM and memory level", "typed next"),
            ],
        ),
        Operation::Decrypt
        | Operation::Check
        | Operation::Rekey
        | Operation::Wallets
        | Operation::Repair => (
            "Which settings was the container made with?",
            [
                Answer::new("PIM 0 and memory level 0, the defaults", time),
                Answer::new("Other settings", "typed next"),
            ],
        ),
    };
    let question = Question {
        text,
        explanation: &[],
        // What the settings mean is documentation, not text to read during the work.
        more: Some(readme::SETTINGS),
        record: None,
    };
    Ok(input.choose(&question, &answers)? == 1)
}

/// Asks for a PIM and a memory level until this computer can run them. At a terminal that redraws
/// lines, the questions are erased afterwards: the settings shown next record the answers.
fn ask_own(input: &mut Input) -> Result<WorkFactor, Failure> {
    // Both numbers are asked on one step of their own in a command shown one step at a time.
    flow::step();
    let mut drawn_lines = 0;
    let work = loop {
        let pim = ask_number(
            input,
            &Question {
                text: &format!("PIM, {}", pim_range()),
                explanation: &["Each step adds the default work again: 1 doubles the time."],
                more: None,
                record: None,
            },
            "PIM: ",
            &mut drawn_lines,
        )?;
        let sizes = format!("{}.", memory_levels());
        let available = highest_available_level().map(|highest| {
            format!("This computer has the memory for level {highest} at most now.")
        });
        let mut explanation = vec![sizes.as_str()];
        explanation.extend(available.as_deref());
        let level = ask_number(
            input,
            &Question {
                text: &format!("Memory level, {}", level_range()),
                explanation: &explanation,
                more: None,
                record: None,
            },
            "Memory level: ",
            &mut drawn_lines,
        )?;
        let checked = WorkFactor::new(pim, level)
            .map_err(Failure::from)
            .and_then(|work| check_resources(work).map(|()| work));
        match checked {
            Ok(work) => break work,
            Err(failure) => {
                eprintln!();
                drawn_lines += 1 + style::retry(format!(
                    "{}. Please choose again.",
                    failure.message.trim_end_matches('.')
                ));
            }
        }
    };
    if choice::can_run() && !flow::is_active() {
        choice::write_control(&choice::redraw_from(drawn_lines))?;
    }
    Ok(work)
}

/// Asks `question` for a whole number, again until one is typed, and adds the lines it drew to
/// `drawn_lines`: the question block, and a line for every prompt and every retry.
fn ask_number(
    input: &mut Input,
    question: &Question,
    prompt: &str,
    drawn_lines: &mut usize,
) -> Result<u32, Failure> {
    *drawn_lines += choice::draw_question(question);
    loop {
        let typed = input.visible(prompt)?;
        *drawn_lines += 1;
        match typed.trim().parse() {
            Ok(number) => return Ok(number),
            Err(_) => *drawn_lines += style::retry("Type a whole number."),
        }
    }
}

/// The rounds of an operation: twelve, or for an encryption twelve more to check it.
fn rounds_of(operation: Operation) -> u32 {
    match operation {
        Operation::Encrypt | Operation::RekeyNew | Operation::New => ENCRYPTION_ROUNDS,
        Operation::Decrypt
        | Operation::Check
        | Operation::Rekey
        | Operation::Wallets
        | Operation::Repair => ROUNDS,
    }
}

/// States the settings, the work and the expected time, and for an encryption with more memory
/// than the default, that recovery will need it too. Settings the person was asked for are an
/// answer of the summary, in cyan like the others; the erased question leaves no other trace.
fn show(work: WorkFactor, operation: Operation, asked: bool) {
    let rounds = rounds_of(operation);
    let how = match operation {
        Operation::Encrypt | Operation::RekeyNew | Operation::New => {
            "24 rounds (12 to encrypt, 12 to check)"
        }
        Operation::Decrypt | Operation::Check | Operation::Rekey => "12 rounds",
        Operation::Wallets => "12 rounds a wallet",
        Operation::Repair => "12 rounds a candidate",
    };
    // The estimate is for the twelve rounds of one pass through the cipher.
    let (low, high) = work.estimated_seconds();
    let scale = u64::from(rounds / ROUNDS);
    let gray = |text: String| paint(MUTED, text);

    let memory = format!("({})", work.memory_text());
    let settings = if asked {
        paint(
            ACCENT,
            format!(
                "PIM {} · memory level {} {memory}",
                work.pim(),
                work.memory_level()
            ),
        )
    } else {
        format!(
            "PIM {} {} memory level {} {}",
            work.pim(),
            gray("·".into()),
            work.memory_level(),
            gray(memory)
        )
    };
    style::fact("Settings", settings);
    style::fact(
        "Work",
        format!("{how} {} {} Argon2 passes", gray("×".into()), work.passes()),
    );
    style::fact(
        "Time",
        format!(
            "about {} {}",
            time_range(low * scale, high * scale),
            gray("on a current computer".into())
        ),
    );
    if let Some(enforced) = isolation_text(crate::protect::isolation()) {
        style::fact("Isolation", enforced);
    }
    let locking = mhfe::memory::LockProbe::default().run(Tier::Startup);
    style::fact(
        "Secrets",
        locked_memory_text(locking, crate::protect::lock_limit()),
    );
    eprintln!();
    let refuted = crate::protect::isolation_refuted();
    if !refuted.is_empty() {
        // The summary above states only what the probes confirmed (protect::verify_isolation).
        style::warn(
            &format!(
                "Isolation is weaker than the kernel reported: {}.",
                refuted.names().join(", ")
            ),
            "",
        );
        eprintln!();
    }
    if matches!(
        operation,
        Operation::Encrypt | Operation::RekeyNew | Operation::New
    ) && work.memory_level() > 0
    {
        style::warn(
            &format!(
                "Recovery will need a computer with {} of free memory.",
                work.memory_text()
            ),
            "",
        );
        eprintln!();
    }
}

/// What the kernel forbids this command, for the summary; `None` where it forbids nothing, as
/// outside Linux.
fn isolation_text(isolation: crate::protect::Isolation) -> Option<String> {
    // "New": neither boundary revokes descriptors opened before, such as a redirected standard
    // output. Each text keeps the summary line within 78 columns, its label included.
    let forbidden = match (
        isolation.empty_network,
        isolation.no_network,
        isolation.no_writes,
    ) {
        (true, true, true) => "isolated network, no new sockets or file writes",
        (true, true, false) => "isolated network, no new sockets",
        (true, false, true) => "isolated network, no new file writes",
        (true, false, false) => "isolated network",
        (false, true, true) => "no new sockets or file writes",
        (false, true, false) => "no new sockets",
        (false, false, true) => "no new file writes",
        (false, false, false) => return None,
    };
    Some(format!("{forbidden} {}", paint(MUTED, "(kernel-enforced)")))
}

/// Whether typed secrets are kept in locked memory, out of swap, as the library's memory-locking
/// check finds it on a buffer of one typed line's size (mhfe::memory::LockProbe), with the most
/// memory the process may lock when it is refused. A later buffer that cannot be locked is said
/// when it is read (terminal::note_unlocked). The Argon2 work area is far too large to lock; the
/// warning about unencrypted swap covers it.
fn locked_memory_text(outcome: ComponentOutcome, lock_limit: Option<u64>) -> String {
    match outcome {
        ComponentOutcome::Passed => "kept in locked memory, out of swap".to_owned(),
        ComponentOutcome::Failed(_) | ComponentOutcome::Warning(_) => {
            let limit = lock_limit
                .map(|bytes| format!(" (lock limit {})", byte_size(bytes)))
                .unwrap_or_default();
            paint(WARNING, format!("! not locked, may reach swap{limit}"))
        }
        ComponentOutcome::NotAvailable(_) | ComponentOutcome::NotRun(_) => {
            paint(MUTED, "not locked on this system")
        }
    }
}

/// "64 KiB", "8 MiB": a power-of-two size in the largest unit it fills.
fn byte_size(bytes: u64) -> String {
    const KIB: u64 = 1 << 10;
    const MIB: u64 = 1 << 20;
    match bytes {
        b if b >= MIB => format!("{} MiB", b / MIB),
        b if b >= KIB => format!("{} KiB", b / KIB),
        b => format!("{b} bytes"),
    }
}

/// Refuses at once, before any secret is asked for, a memory level that this build or computer
/// cannot run. Nothing is allocated yet.
fn check_resources(work: WorkFactor) -> Result<(), Failure> {
    check_can_run(work).map_err(with_level_hint)
}

/// Reserves the Argon2 memory, after the inputs have been read and checked.
pub fn reserve_memory(work: WorkFactor) -> Result<Mhfe<NativeEngine>, Failure> {
    Mhfe::new(work).map_err(with_level_hint)
}

/// Adds the highest memory level this computer can use now to a refusal for lack of free memory.
/// Only that refusal rests on the reported free memory. After a failed reservation that figure has
/// just proved too high, and a level above the highest this build runs is refused whatever memory
/// is free, so neither gets a level to try (AUD-005-UI001).
fn with_level_hint(error: mhfe::MhfeError) -> Failure {
    let lower_level_helps = matches!(error, mhfe::MhfeError::NotEnoughMemory { .. });
    let mut failure = Failure::from(error);
    if let Some(highest) = highest_available_level().filter(|_| lower_level_helps) {
        failure.message.push_str(&format!(
            ". The highest memory level this computer can use now is {highest}."
        ));
    }
    failure
}

/// The memory of the first levels and the last, from the library's work factors, such as
/// "0 = 2 GiB, 1 = 3 GiB, 2 = 4 GiB, 3 = 6 GiB, 4 = 8 GiB, ... 21 = 3 TiB".
fn memory_levels() -> String {
    /// Levels listed before the ellipsis.
    const FIRST: u32 = 5;
    let size = |level: u32| format!("{level} = {}", memory_text(level));
    let first: Vec<String> = (0..FIRST).map(size).collect();
    format!("{}, ... {}", first.join(", "), size(MAX_MEMORY_LEVEL))
}

/// The memory of `level`: "2 GiB", and in whole tebibytes from 1 TiB on, as the highest levels are.
pub fn memory_text(level: u32) -> String {
    WorkFactor::new(0, level).map_or_else(|_| String::new(), WorkFactor::memory_text)
}

/// The PIMs a container takes: "0 to 1023".
pub fn pim_range() -> String {
    format!("0 to {}", mhfe::MAX_PIM)
}

/// The memory levels a container takes: "0 to 21".
pub fn level_range() -> String {
    format!("0 to {MAX_MEMORY_LEVEL}")
}

/// "1 to 2 minutes", "17 to 34 hours", "3 to 6 days": both ends in the unit that suits the
/// longer one, rounded to whole units.
pub fn time_range(low_seconds: u64, high_seconds: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    let (unit_seconds, unit) = match high_seconds {
        s if s < 2 * HOUR => (MINUTE, "minutes"),
        s if s < 3 * DAY => (HOUR, "hours"),
        _ => (DAY, "days"),
    };
    let low = (low_seconds / unit_seconds).max(1);
    let high = (high_seconds / unit_seconds).max(low);
    format!("{low} to {high} {unit}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mhfe::MhfeError;

    const GIB: u64 = 1 << 30;

    /// Every isolation text fits one summary line of 78 columns with its "  Isolation  " label.
    #[test]
    fn the_isolation_line_fits_the_summary() {
        const LABEL: usize = "  Isolation  ".len();
        for bits in 0..8u8 {
            let isolation = crate::protect::Isolation {
                empty_network: bits & 1 != 0,
                no_network: bits & 2 != 0,
                no_writes: bits & 4 != 0,
            };
            if let Some(text) = isolation_text(isolation) {
                assert!(LABEL + style::visible_width(&text) <= 78, "{text}");
            }
        }
    }

    /// Every text of the locked-memory fact fits one summary line of 78 columns with its label.
    #[test]
    fn the_locked_memory_line_fits_the_summary() {
        const LABEL: usize = "  Secrets    ".len();
        for outcome in [
            ComponentOutcome::Passed,
            ComponentOutcome::Warning("refused".to_owned()),
            ComponentOutcome::NotAvailable("Windows".to_owned()),
        ] {
            // A limit as long as one can be written.
            let text = locked_memory_text(outcome, Some(1023 << 20));
            assert!(LABEL + style::visible_width(&text) <= 78, "{text}");
        }
        assert_eq!(
            locked_memory_text(ComponentOutcome::Passed, None),
            "kept in locked memory, out of swap"
        );
        let refused = locked_memory_text(ComponentOutcome::Warning("x".to_owned()), Some(64 << 10));
        assert!(refused.contains("! not locked, may reach swap (lock limit 64 KiB)"));
        assert_eq!(byte_size(64 << 10), "64 KiB");
        assert_eq!(byte_size(8 << 20), "8 MiB");
        assert_eq!(byte_size(512), "512 bytes");
    }

    const LEVEL_HINT: &str = "The highest memory level this computer can use now";

    /// AUD-005-UI001: only a refusal for lack of reported free memory suggests a level.
    #[test]
    fn only_a_free_memory_refusal_suggests_a_level() {
        let no_reservation = with_level_hint(MhfeError::MemoryAllocation { bytes: 2 * GIB });
        assert!(!no_reservation.message.contains(LEVEL_HINT));

        let not_enough = with_level_hint(MhfeError::NotEnoughMemory {
            needed_bytes: 2 * GIB,
            available_bytes: GIB,
        });
        // The hint depends on what this computer reports now; it appears exactly when a level fits.
        assert_eq!(
            not_enough.message.contains(LEVEL_HINT),
            highest_available_level().is_some()
        );
    }

    #[test]
    fn time_ranges_use_one_readable_unit() {
        assert_eq!(time_range(60, 120), "1 to 2 minutes");
        let highest_pim = WorkFactor::new(1023, 0).unwrap().estimated_seconds();
        assert_eq!(time_range(highest_pim.0, highest_pim.1), "17 to 34 hours");
        let highest_memory = WorkFactor::new(0, 21).unwrap().estimated_seconds();
        assert_eq!(
            time_range(highest_memory.0, highest_memory.1),
            "25 to 51 hours"
        );
        assert_eq!(time_range(3 * 86_400, 6 * 86_400), "3 to 6 days");
    }
}
