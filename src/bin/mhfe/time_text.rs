//! Times as the screens and the help say them, from one set of units: an estimate as a range of
//! whole units, and a measured duration.

use mhfe::{WorkFactor, ROUNDS};

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

/// "1 to 2 minutes", "17 to 34 hours", "3 to 6 days": both ends in the unit that suits the
/// longer one, rounded to whole units.
pub fn range(low_seconds: u64, high_seconds: u64) -> String {
    let (unit_seconds, unit) = match high_seconds {
        s if s < 2 * HOUR => (MINUTE, "minutes"),
        s if s < 3 * DAY => (HOUR, "hours"),
        _ => (DAY, "days"),
    };
    let low = (low_seconds / unit_seconds).max(1);
    let high = (high_seconds / unit_seconds).max(low);
    format!("{low} to {high} {unit}")
}

/// The estimated time of `rounds` rounds at `work`, in passes of 12 through the cipher, as a
/// range: "1 to 2 minutes" for a recovery at the defaults.
pub fn of_rounds(work: WorkFactor, rounds: u32) -> String {
    let (low, high) = work.estimated_seconds();
    let passes = u64::from(rounds / ROUNDS);
    range(low * passes, high * passes)
}

/// "45 s", "3 min 20 s", "2 h 5 min", "1 day 3 h".
pub fn duration(seconds: u64) -> String {
    match seconds {
        s if s < MINUTE => format!("{s} s"),
        s if s < HOUR => format!("{} min {} s", s / MINUTE, s % MINUTE),
        s if s < DAY => format!("{} h {} min", s / HOUR, (s % HOUR) / MINUTE),
        s => {
            let days = s / DAY;
            let unit = if days == 1 { "day" } else { "days" };
            format!("{days} {unit} {} h", (s % DAY) / HOUR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mhfe::ENCRYPTION_ROUNDS;

    #[test]
    fn ranges_use_one_readable_unit() {
        assert_eq!(range(60, 120), "1 to 2 minutes");
        let highest_pim = WorkFactor::new(1023, 0).unwrap().estimated_seconds();
        assert_eq!(range(highest_pim.0, highest_pim.1), "17 to 34 hours");
        let highest_memory = WorkFactor::new(0, 21).unwrap().estimated_seconds();
        assert_eq!(range(highest_memory.0, highest_memory.1), "25 to 51 hours");
        assert_eq!(range(3 * 86_400, 6 * 86_400), "3 to 6 days");
    }

    /// The help, the menu and the settings summary say the same estimate, from the same rounds
    /// (AUD-023-ARC008); an estimate that is not a whole number of minutes rounds down at both
    /// ends.
    #[test]
    fn the_estimate_of_rounds_is_said_once() {
        let defaults = WorkFactor::default();
        assert_eq!(of_rounds(defaults, ROUNDS), "1 to 2 minutes");
        assert_eq!(of_rounds(defaults, ENCRYPTION_ROUNDS), "2 to 4 minutes");
        assert_eq!(range(90, 150), "1 to 2 minutes");
    }

    #[test]
    fn durations_read_in_the_largest_units() {
        assert_eq!(duration(45), "45 s");
        assert_eq!(duration(200), "3 min 20 s");
        assert_eq!(duration(7_500), "2 h 5 min");
        assert_eq!(duration(97_200), "1 day 3 h");
        assert_eq!(duration(3 * 86_400), "3 days 0 h");
    }
}
