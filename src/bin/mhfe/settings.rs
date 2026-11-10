//! The PIM and memory-level options shared by every command that runs MHFE. A person at a
//! terminal who gives neither is asked: the defaults are chosen unless they pick their own.

use anstream::eprintln;
use clap::Args;
use mhfe::engine::{check_can_run, highest_available_level, reserve};
use mhfe::self_check::{ComponentCheck, ComponentOutcome, Tier};
use mhfe::{estimated_seconds, memory_bytes, ENCRYPTION_ROUNDS, ROUNDS};
use mhfe_core::{Mhfe, NativeArgon2, WorkFactor};

use crate::choice::{self, Answer, Question};
use crate::exit::Failure;
use crate::flow;
use crate::protect::{Swap, SwapArea};
use crate::readme;
use crate::style::{self, paint, ACCENT, MUTED, WARNING};
use crate::terminal::Input;

#[derive(Args, Clone, Copy)]
pub(crate) struct Settings {
    // Options rather than defaults, so that a command can tell whether the person gave them.
    #[arg(long, value_name = "N", help = pim_summary(), long_help = pim_help())]
    pub pim: Option<u32>,

    #[arg(long = "mem", value_name = "LEVEL", help = memory_level_summary(), long_help = memory_level_help())]
    pub memory_level: Option<u32>,
}

/// The first sentence of the PIM's help, which `-h` shows alone.
fn pim_summary() -> String {
    format!("Pass multiplier, {} (default 0)", pim_range())
}

fn pim_help() -> String {
    style::option_help(&[
        &format!("{}.", pim_summary()),
        "Every step adds the default work again: PIM 1 doubles the time of the encryption and \
         of every recovery, PIM 9 makes it ten times as long. Each guess of the password costs \
         an attacker the same extra time.",
        "Recovery must use the same PIM. At 0 there is nothing to keep; any other value must \
         be remembered or recorded, like part of the password, because it cannot be found from \
         the container. It may be kept secret.",
    ])
}

/// The first sentence of the memory level's help, which `-h` shows alone.
fn memory_level_summary() -> String {
    format!(
        "Memory level, {} (default 0: {})",
        level_range(),
        memory_text(0)
    )
}

fn memory_level_help() -> String {
    style::option_help(&[
        &format!("{}.", memory_level_summary()),
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
    pub(crate) fn work_factor(self) -> Result<WorkFactor, Failure> {
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
pub(crate) enum Operation {
    /// Twelve rounds forward, then twelve backwards to check that they give the phrase back.
    Encrypt,
    /// Twelve rounds backwards for each password.
    Decrypt,
    /// Twelve rounds backwards, compared with a reference instead of shown.
    Check,
    /// `mhfe rekey`, first the twelve rounds backwards of the old container, confirmed but not
    /// shown...
    Rekey,
    /// ...then the 24 rounds of the new one, as an encryption, under the same title.
    RekeyNew,
    /// `mhfe repair`: twelve rounds backwards for each candidate of a search for missing words.
    Repair,
}

impl Operation {
    /// The title of the command, at the top of its screen and of its private screen.
    pub(crate) const fn title(self) -> &'static str {
        match self {
            Operation::Encrypt => "Encrypt a seed phrase",
            Operation::Decrypt => "Recover a seed phrase",
            Operation::Check => "Rehearse a recovery",
            Operation::Rekey | Operation::RekeyNew => "Change the password",
            Operation::Repair => "Repair a container phrase",
        }
    }
}

/// Announces the command, settles its settings and states them with the memory and the expected
/// time, and refuses at once settings that this computer cannot run. A person at a terminal who
/// gave neither setting is asked first: the defaults, or their own. Nothing secret has been asked
/// yet. The format of the container is shown once it is known: after the choice of an encryption,
/// or from the container's word count.
pub(crate) fn choose(
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
    check_resources(work)?;
    Ok(work)
}

/// Says what isolation leaves open, before any secret is typed: a command names a protection
/// only where it is missing, with its settings or, without a summary, on its own.
pub(crate) fn warn_of_isolation_gaps() {
    if let ComponentOutcome::Warning(detail) = crate::protect::IsolationCheck.run(Tier::Startup) {
        style::warn(&format!("Isolation is {detail}."), "");
        eprintln!();
    }
}

/// Says that swap could write memory to a disk unencrypted and asks whether to go on, before any
/// secret is typed; the answer "no", and a script that nobody can ask for, stop the command.
pub(crate) fn ask_about_swap(areas: &[SwapArea]) -> Result<(), Failure> {
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
    ask_to_go_on(
        &headline,
        "Use encrypted swap or none, best a live system from a USB stick.",
    )
}

/// Asks whether to go on although memory may reach a disk, with `headline` saying why and `advice`
/// what to do instead; the answer "no", and a script that nobody can ask for, stop the command.
fn ask_to_go_on(headline: &str, advice: &str) -> Result<(), Failure> {
    if choice::can_run() {
        // Why it matters, Argon2's work area on a disk for years, is in the README.
        style::warn(headline, advice);
        style::more(readme::SAFE_COMPUTER);
        let question = Question::new("Go on although this memory could reach the disk?", "Disk");
        let answers = [
            Answer::new("No", "stop here"),
            Answer::new("Yes", "go on as it is"),
        ];
        if choice::choose_here(&question, &answers, None)? == Some(1) {
            return Ok(());
        }
    }
    Err(Failure::invalid_input(format!("{headline} {advice}")))
}

/// Asks whether to keep the defaults; true when the person wants to give their own settings. The
/// question is erased once answered: the settings shown next record the answer.
fn ask_for_own(
    input: &mut Input,
    operation: Operation,
    defaults: WorkFactor,
) -> Result<bool, Failure> {
    let (low, high) = estimated_seconds(defaults);
    let scale = u64::from(rounds_of(operation) / ROUNDS);
    let time = format!("about {}", time_range(low * scale, high * scale));
    let (text, answers) = match operation {
        Operation::Encrypt | Operation::RekeyNew => (
            "Which settings should protect the phrase?",
            [
                Answer::new("PIM 0 and memory level 0 (recommended)", time),
                Answer::new("My own PIM and memory level", "typed next"),
            ],
        ),
        Operation::Decrypt | Operation::Check | Operation::Rekey | Operation::Repair => (
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

/// The settings that go with another password of a recovery: the first password's, `first`, on
/// Enter, or a PIM and a memory level typed next, which this computer must be able to run. They
/// are neither stated nor recorded, as the passwords after the first leave no trace in the
/// summary (decrypt.rs).
pub(crate) fn choose_another(input: &mut Input, first: WorkFactor) -> Result<WorkFactor, Failure> {
    let question = Question {
        text: "Which settings go with this password?",
        explanation: &[],
        more: Some(readme::SETTINGS),
        record: None,
    };
    let answers = [
        Answer::new(
            format!(
                "PIM {} and memory level {}",
                first.pim(),
                first.memory_level()
            ),
            "as for the first password",
        ),
        Answer::new("Other settings", "typed next"),
    ];
    if input.choose(&question, &answers)? == 0 {
        return Ok(first);
    }
    ask_own(input)
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
        Operation::Encrypt | Operation::RekeyNew => ENCRYPTION_ROUNDS,
        Operation::Decrypt | Operation::Check | Operation::Rekey | Operation::Repair => ROUNDS,
    }
}

/// States the settings, the expected time where they make it longer than the default's, a
/// protection that is missing, and for an encryption with more memory than the default, that
/// recovery will need it too. Settings the person was asked for are an answer of the summary, in
/// cyan like the others; the erased question leaves no other trace.
fn show(work: WorkFactor, operation: Operation, asked: bool) {
    let rounds = rounds_of(operation);
    let each = match operation {
        Operation::Decrypt => " a password",
        Operation::Repair => " a candidate",
        _ => "",
    };
    // The estimate is for the twelve rounds of one pass through the cipher.
    let (low, high) = estimated_seconds(work);
    let scale = u64::from(rounds / ROUNDS);
    let gray = |text: String| paint(MUTED, text);

    let memory = format!("({})", mhfe::memory_text(memory_bytes(work)));
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
    // The time only where the settings make the work longer than the default's (WF-5).
    if work.pim() > 0 || work.memory_level() > 0 {
        style::fact(
            "Time",
            format!(
                "about {}{each} {}",
                time_range(low * scale, high * scale),
                gray("on a current computer".into())
            ),
        );
    }
    // A protection is named only where it is missing: the gaps of isolation are warned of below.
    let locking = mhfe::memory::LockProbe::default().run(Tier::Startup);
    if locking != ComponentOutcome::Passed {
        style::fact(
            "Secrets",
            locked_memory_text(locking, crate::protect::lock_limit()),
        );
    }
    if crate::protect::swap() == Some(Swap::Allowed) {
        style::fact(
            "Swap",
            paint(WARNING, "! secrets may reach the disk, as you chose"),
        );
    }
    eprintln!();
    warn_of_isolation_gaps();
    if matches!(operation, Operation::Encrypt | Operation::RekeyNew) && work.memory_level() > 0 {
        style::warn(
            &format!(
                "Recovery will need a computer with {} of free memory.",
                mhfe::memory_text(memory_bytes(work))
            ),
            "",
        );
        eprintln!();
    }
}

/// Whether typed secrets are kept in locked memory, out of swap, as the library's memory-locking
/// check finds it on a buffer of one typed line's size (mhfe::memory::LockProbe), with the most
/// memory the process may lock when it is refused. A later buffer that cannot be locked is said
/// when it is read (terminal::note_unlocked). The Argon2 work area is locked only where the limit
/// holds all of it; swap on a disk is forbidden or asked about.
fn locked_memory_text(outcome: ComponentOutcome, lock_limit: Option<u64>) -> String {
    match outcome {
        ComponentOutcome::Passed => "kept in locked memory, out of swap".to_owned(),
        _ => {
            let limit = lock_limit
                .map(|bytes| format!(" (lock limit {})", byte_size(bytes)))
                .unwrap_or_default();
            paint(WARNING, format!("! not locked, may reach swap{limit}"))
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
pub(crate) fn reserve_memory(work: WorkFactor) -> Result<Mhfe<NativeArgon2>, Failure> {
    Ok(Mhfe::with_engine(work, reserve_engine(work)?))
}

/// The Argon2 engine with the memory of `work` reserved, for a caller that runs it at several
/// settings up to that memory.
pub(crate) fn reserve_engine(work: WorkFactor) -> Result<NativeArgon2, Failure> {
    let engine = reserve(work).map_err(with_level_hint)?;
    // Windows has no way to forbid a program its page file: a locked work area stays out of it.
    if cfg!(windows) && !engine.is_locked() {
        ask_to_go_on(
            "Windows did not lock Argon2's memory, so it could reach the page file.",
            "Use BitLocker or no page file.",
        )?;
    }
    Ok(engine)
}

/// Adds the highest memory level this computer can use now to a refusal for lack of free memory.
/// Only that refusal rests on the reported free memory. After a failed reservation that figure has
/// just proved too high, and a level above the highest this build runs is refused whatever memory
/// is free, so neither gets a level to try (AUD-005-UI001).
pub(crate) fn with_level_hint(error: mhfe::MhfeError) -> Failure {
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
    let last = size(WorkFactor::MAX_MEMORY_LEVEL);
    format!("{}, ... {last}", first.join(", "))
}

/// The memory of `level`: "2 GiB", and in whole tebibytes from 1 TiB on, as the highest levels are.
pub(crate) fn memory_text(level: u32) -> String {
    WorkFactor::new(0, level).map_or_else(
        |_| String::new(),
        |work| mhfe::memory_text(memory_bytes(work)),
    )
}

/// The PIMs a container takes: "0 to 1023".
pub(crate) fn pim_range() -> String {
    format!("0 to {}", WorkFactor::MAX_PIM)
}

/// The memory levels a container takes: "0 to 21".
pub(crate) fn level_range() -> String {
    format!("0 to {}", WorkFactor::MAX_MEMORY_LEVEL)
}

/// "1 to 2 minutes", "17 to 34 hours", "3 to 6 days": both ends in the unit that suits the
/// longer one, rounded to whole units.
pub(crate) fn time_range(low_seconds: u64, high_seconds: u64) -> String {
    use crate::terminal::{DAY, HOUR, MINUTE};
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

    /// Every text of the locked-memory fact fits one summary line of 78 columns with its label.
    #[test]
    fn the_locked_memory_line_fits_the_summary() {
        const LABEL: usize = "  Secrets    ".len();
        for outcome in [
            ComponentOutcome::Passed,
            ComponentOutcome::Warning("refused".to_owned()),
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
        let highest_pim = estimated_seconds(WorkFactor::new(1023, 0).unwrap());
        assert_eq!(time_range(highest_pim.0, highest_pim.1), "17 to 34 hours");
        let highest_memory = estimated_seconds(WorkFactor::new(0, 21).unwrap());
        assert_eq!(
            time_range(highest_memory.0, highest_memory.1),
            "25 to 51 hours"
        );
        assert_eq!(time_range(3 * 86_400, 6 * 86_400), "3 to 6 days");
    }
}
