//! The PIM and memory-level options shared by every command that runs MHFE.

use anstream::eprintln;
use clap::Args;
use mhfe::engine::HIGHEST_MEMORY_LEVEL;
use mhfe::engine::{available_memory_bytes, check_can_run, NativeEngine};
use mhfe::{Mhfe, WorkFactor, ENCRYPTION_ROUNDS, ROUNDS, SUITE_ID};

use crate::exit::Failure;
use crate::style::{self, paint, MUTED};

const GIB: u64 = 1 << 30;

#[derive(Args, Clone, Copy)]
pub struct Settings {
    /// Pass multiplier, 0 to 1023 (default 0)
    #[arg(
        long,
        value_name = "N",
        default_value_t = 0,
        hide_default_value = true,
        long_help = pim_help()
    )]
    pub pim: u32,

    /// Memory level, 0 to 21 (default 0: 2 GiB)
    #[arg(
        long = "mem",
        value_name = "LEVEL",
        default_value_t = 0,
        hide_default_value = true,
        long_help = memory_level_help()
    )]
    pub memory_level: u32,
}

fn pim_help() -> String {
    style::option_help(&[
        "Pass multiplier, 0 to 1023 (default 0).",
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
        "Memory level, 0 to 21 (default 0: 2 GiB).",
        "The memory of every Argon2 call, doubling every two levels; the time grows in \
         proportion to it:",
        "0 = 2 GiB, 1 = 3 GiB, 2 = 4 GiB, 3 = 6 GiB, 4 = 8 GiB, ... 21 = 3 TiB",
        "Recovery must use the same level and needs that much free memory, so choose a level \
         that the computer you will recover on can provide. The browser tools support level 0 \
         only. At 0 there is nothing to keep; any other level must be remembered or recorded \
         like the PIM, and it may be kept secret.",
    ])
}

impl Settings {
    pub fn work_factor(self) -> Result<WorkFactor, Failure> {
        Ok(WorkFactor::new(self.pim, self.memory_level)?)
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
}

/// States the suite, the settings, the memory and the expected time before anything starts.
pub fn announce(work: WorkFactor, operation: Operation) {
    let (title, rounds, how) = match operation {
        Operation::Encrypt => (
            "Encrypt a recovery phrase",
            ENCRYPTION_ROUNDS,
            "24 rounds (12 to encrypt, 12 to check)",
        ),
        Operation::Decrypt => ("Recover a recovery phrase", ROUNDS, "12 rounds"),
        Operation::Check => ("Rehearse a recovery", ROUNDS, "12 rounds"),
    };
    // The estimate is for the twelve rounds of one pass through the cipher.
    let (low, high) = work.estimated_seconds();
    let scale = u64::from(rounds / ROUNDS);
    let gray = |text: String| paint(MUTED, text);

    style::title(title);
    style::fact("Suite", SUITE_ID);
    style::fact(
        "Settings",
        format!(
            "PIM {} {} memory level {} {}",
            work.pim(),
            gray("·".into()),
            work.memory_level(),
            gray(format!("({} GiB)", work.memory_bytes() / GIB))
        ),
    );
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
    eprintln!();
    if matches!(operation, Operation::Encrypt) && work.memory_level() > 0 {
        style::warn(
            &format!(
                "Recovery will need a computer with {} GiB of free memory.",
                work.memory_bytes() / GIB
            ),
            "One must still be available when you recover, perhaps years from now.",
        );
        eprintln!();
    }
}

/// Refuses at once, before any secret is asked for, a memory level that this build or computer
/// cannot run. Nothing is allocated yet.
pub fn check_resources(work: WorkFactor) -> Result<(), Failure> {
    check_can_run(work).map_err(with_level_hint)
}

/// Reserves the Argon2 memory, after the inputs have been read and checked.
pub fn reserve_memory(work: WorkFactor) -> Result<Mhfe<NativeEngine>, Failure> {
    Mhfe::new(work).map_err(with_level_hint)
}

/// Adds the highest memory level this computer can use now to a refusal for lack of free memory.
/// Only that refusal rests on the reported free memory. After a failed reservation that figure has
/// just proved too high, and a processor refusal has nothing to do with memory, so neither gets a
/// level to try (AUD-005-UI001).
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

/// The highest memory level whose memory the computer reports as free, if any.
pub fn highest_available_level() -> Option<u32> {
    let available = available_memory_bytes()?;
    (0..=HIGHEST_MEMORY_LEVEL)
        .rev()
        .filter_map(|level| WorkFactor::new(0, level).ok())
        .find(|work| work.memory_bytes() <= available)
        .map(WorkFactor::memory_level)
}

/// The settings that differ from the defaults, such as "PIM 1, memory level 1", or `None` when
/// both are 0. Only these need remembering: the suite is fixed and the original's length is
/// detected, so with the defaults the 24 words and the password are all that recovery needs.
pub fn changed_settings(work: WorkFactor) -> Option<String> {
    let mut values = Vec::new();
    if work.pim() != 0 {
        values.push(format!("PIM {}", work.pim()));
    }
    if work.memory_level() != 0 {
        values.push(format!("memory level {}", work.memory_level()));
    }
    (!values.is_empty()).then(|| values.join(", "))
}

/// "1 to 2 minutes", "17 to 34 hours", "3 to 6 days": both ends in the unit that suits the
/// longer one, rounded to whole units.
fn time_range(low_seconds: u64, high_seconds: u64) -> String {
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
