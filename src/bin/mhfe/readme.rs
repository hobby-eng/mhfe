//! The README sections that the screens link to. While a command runs, a screen names a point in
//! a short line and links here for the explanation, so that the work is not buried in text. A test
//! checks that every link leads to a heading of README.md.

/// A section of the README on GitHub, by the anchor GitHub gives its heading.
macro_rules! section {
    ($anchor:literal) => {
        concat!("https://github.com/hobby-eng/mhfe#", $anchor)
    };
}

/// A trusted offline computer, and why unencrypted swap matters.
pub const SAFE_COMPUTER: &str = section!("getting-started");
/// What PIM and memory level change, and that recovery needs them again.
pub const SETTINGS: &str = section!("settings-pim-and-memory-level");
/// A 24-word container or one as long as the phrase: what each gives and costs.
pub const CONTAINER_LENGTH: &str = section!("24-words-or-the-same-length");
/// Making a password, and what makes one strong.
pub const PASSWORD: &str = section!("mhfe-password");
/// What to keep after an encryption, and the rehearsal before relying on it.
pub const ENCRYPT: &str = section!("mhfe-encrypt");
/// What a check can and cannot tell.
pub const CHECK: &str = section!("mhfe-check");
/// What a recovered phrase that is not verified means.
pub const DECRYPT: &str = section!("mhfe-decrypt");
/// What a new password or new settings change, and what they do not.
pub const REKEY: &str = section!("mhfe-rekey");
/// A new wallet, and what its wallet check gives and costs.
pub const NEW: &str = section!("mhfe-new");
/// What hidden wallets are, and how to keep them hidden.
pub const WALLETS: &str = section!("mhfe-wallets");
/// What a failed self-test means.
pub const SELF_TEST: &str = section!("mhfe-self-test");

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "https://github.com/hobby-eng/mhfe#";
    const ALL: &[&str] = &[
        SAFE_COMPUTER,
        SETTINGS,
        CONTAINER_LENGTH,
        PASSWORD,
        ENCRYPT,
        CHECK,
        DECRYPT,
        REKEY,
        NEW,
        WALLETS,
        SELF_TEST,
    ];

    /// The anchor GitHub gives a heading: lower case, spaces as hyphens, and only letters,
    /// digits, hyphens and underscores kept, so "`mhfe check`" becomes "mhfe-check".
    fn anchor(heading: &str) -> String {
        heading
            .trim()
            .to_lowercase()
            .chars()
            .filter_map(|c| match c {
                ' ' => Some('-'),
                c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn every_link_leads_to_a_readme_heading() {
        let readme = include_str!("../../../README.md");
        let anchors: Vec<String> = readme
            .lines()
            .filter_map(|line| line.strip_prefix('#'))
            .map(|line| anchor(line.trim_start_matches('#')))
            .collect();
        for link in ALL {
            let wanted = link.strip_prefix(PREFIX).unwrap();
            assert!(
                anchors.iter().any(|found| found == wanted),
                "README.md has no heading for #{wanted}"
            );
        }
    }

    #[test]
    fn anchors_follow_github() {
        assert_eq!(anchor(" `mhfe check`"), "mhfe-check");
        assert_eq!(
            anchor(" Settings: PIM and memory level"),
            "settings-pim-and-memory-level"
        );
        assert_eq!(
            anchor(" 24 words or the same length"),
            "24-words-or-the-same-length"
        );
    }
}
