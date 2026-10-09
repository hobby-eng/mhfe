//! The sets of checks each front end runs. A set holds the checks of the parts its front end
//! computes, and each is built only with its feature: a browser module's WebAssembly carries the
//! checks and vectors of its own parts and no others.
//!
//! - [`hashes`]: the cipher's hashes alone.
//! - [`core()`]: everything the encryption, recovery, rehearsal, rekey and hidden-wallet operations
//!   compute, with Argon2 added by the caller: [`crate::engine::NativeArgon2Check`] natively, the
//!   page's `BrowserArgon2Check` in a browser, or none for a quick check without Argon2.
//! - [`repair`]: the repair words and the BIP39 word list they are written in.
//! - [`passwords`]: the password encoding, the check word, the generator, the word hints and the
//!   random source.
//! - [`wallet`]: the word list, the wallet hashes, seeds, keys and addresses, the address search
//!   an address check states, the wallet check, the chosen word, the word hints and the random
//!   source.
//! - [`native`]: everything the command-line tool computes.
//!
//! The parts of several sets are checked once when the sets are merged ([`SelfCheck::merge`]).

use super::{ComponentCheck, ComponentOutcome, SelfCheck, Tier};
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-passwords",
    feature = "browser-wallet"
))]
use crate::random::{RandomSource, RandomSourceCheck};

/// A part that this run leaves out, with the reason, so that the report still names it.
pub struct NotChecked {
    id: &'static str,
    label: &'static str,
    reason: &'static str,
}

impl NotChecked {
    pub fn new(id: &'static str, label: &'static str, reason: &'static str) -> Self {
        Self { id, label, reason }
    }
}

impl ComponentCheck for NotChecked {
    fn id(&self) -> &'static str {
        self.id
    }

    fn label(&self) -> &'static str {
        self.label
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        ComponentOutcome::NotRun(self.reason.to_owned())
    }
}

/// The parts of encryption, recovery, the rehearsal check, rekey and hidden wallets. `argon2` is
/// the check of the Argon2 engine the operations will use; without one, the report lists Argon2
/// as not run.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub fn core<'a>(argon2: Option<Box<dyn ComponentCheck + 'a>>) -> SelfCheck<'a> {
    let argon2 = argon2.unwrap_or_else(|| {
        Box::new(NotChecked::new(
            "argon2",
            "Argon2id",
            "this check leaves Argon2 out",
        ))
    });
    SelfCheck::new()
        .with(crate::mhfe::known_answers::CipherHashesCheck::new())
        .with(argon2)
        .with(crate::mhfe::known_answers::CipherRoundsCheck::new())
        .with(crate::mhfe::known_answers::FormatsCheck::new())
        .with(crate::container::known_answers::ContainerFactsCheck::new())
        .with(crate::operation::known_answers::KeepCheck::new())
        .with(crate::password::known_answers::PasswordUnicodeCheck::new())
        .with(crate::phrase::known_answers::WordListCheck::new())
        .with(crate::repair::known_answers::RepairWordsCheck::new())
        .with(crate::search::known_answers::ContainerSearchCheck::new())
        .with(crate::check_word::known_answers::CheckWordCheck::new())
        .merge(wallet_keys())
        .with(crate::wallet_check::known_answers::WalletCheckProfile::new())
        .with(crate::hidden::known_answers::HiddenWalletsCheck::new())
        .with(crate::rekey::known_answers::RekeyCheck::new())
        .with(crate::rehearsal::known_answers::RehearsalCheck::new())
}

/// The parts of a wallet's keys, which the core compares with and the wallet tools give: the wallet
/// hashes, seeds, BIP32 keys and addresses.
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-wallet"
))]
fn wallet_keys<'a>() -> SelfCheck<'a> {
    SelfCheck::new()
        .with(crate::wallet::known_answers::WalletHashesCheck::new())
        .with(crate::wallet::known_answers::SeedCheck::new())
        .with(crate::wallet::known_answers::Bip32Check::new())
        .with(crate::wallet::known_answers::AddressesCheck::new())
}

/// The hashes of the cipher alone, SHA-256, HMAC-SHA-256 and BLAKE2b-256: for a program that only
/// hashes, such as one that checks a page's SHA-256 before serving it.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub fn hashes<'a>() -> SelfCheck<'a> {
    SelfCheck::new().with(crate::mhfe::known_answers::CipherHashesCheck::new())
}

/// The parts of the repair words: MHFE-REPAIR-1 and the BIP39 word list.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-repair"))]
pub fn repair<'a>() -> SelfCheck<'a> {
    SelfCheck::new()
        .with(crate::phrase::known_answers::WordListCheck::new())
        .with(crate::repair::known_answers::RepairWordsCheck::new())
}

/// The parts of the password tools. `random` is the source new passwords are drawn from, which
/// the full self-test tries; the startup checks use scripted sources only.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-passwords"))]
pub fn passwords<'a>(random: Option<&'a mut dyn RandomSource>) -> SelfCheck<'a> {
    SelfCheck::new()
        .with(crate::password::known_answers::PasswordUnicodeCheck::new())
        .with(crate::check_word::known_answers::CheckWordCheck::new())
        .with(crate::new_password::known_answers::GeneratorCheck::new())
        .with(crate::word_hints::known_answers::WordHintsCheck::new())
        .with(RandomSourceCheck::new(random))
}

/// The parts of the wallet tools. `random` is the source new phrases are drawn from, which the
/// full self-test tries; the startup checks use scripted sources only.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-wallet"))]
pub fn wallet<'a>(random: Option<&'a mut dyn RandomSource>) -> SelfCheck<'a> {
    SelfCheck::new()
        .with(crate::phrase::known_answers::WordListCheck::new())
        .merge(wallet_keys())
        .with(crate::wallet::known_answers::AddressSearchCheck::new())
        .with(crate::wallet_check::known_answers::WalletCheckProfile::new())
        .with(crate::word_wishes::known_answers::WordWishesCheck::new())
        .with(crate::word_hints::known_answers::WordHintsCheck::new())
        .with(RandomSourceCheck::new(random))
}

/// Everything the command-line tool computes: the core with the native Argon2 engine and its
/// check at 64 and 256 MiB for the full self-test, the password and wallet tools with `random`,
/// the operating system's generator, for the full self-test, and the memory lock. The tool adds
/// the checks of its own process: core dumps, isolation and hidden input.
#[cfg(not(target_arch = "wasm32"))]
pub fn native<'a>(random: Option<&'a mut dyn RandomSource>) -> SelfCheck<'a> {
    core(Some(Box::new(crate::engine::NativeArgon2Check::default())))
        .with(crate::engine::NativeArgon2SizesCheck::default())
        .merge(passwords(random))
        .merge(wallet(None))
        .merge(repair())
        .with(crate::memory::LockProbe::default())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    /// Every check of the plan, in the order the tool runs them, each once.
    const NATIVE_IDS: [&str; 26] = [
        "cipher-hashes",
        "argon2",
        "cipher-rounds",
        "formats",
        "container-facts",
        "keep-advice",
        "password-unicode",
        "bip39-words",
        "repair-words",
        "container-search",
        "password-check-word",
        "wallet-hashes",
        "bip39-seed",
        "bip32",
        "addresses",
        "wallet-check",
        "hidden-wallets",
        "rekey",
        "rehearsal",
        "argon2-sizes",
        "password-generator",
        "word-hints",
        "random-source",
        "address-search",
        "word-wishes",
        "memory-locking",
    ];

    #[test]
    fn the_native_set_has_every_check_once() {
        let set = native(None);
        assert_eq!(set.ids(), NATIVE_IDS);
    }

    #[test]
    fn the_browser_sets_hold_their_own_parts() {
        assert_eq!(hashes().ids(), ["cipher-hashes"]);
        assert_eq!(repair().ids(), ["bip39-words", "repair-words"]);
        assert_eq!(
            passwords(None).ids(),
            [
                "password-unicode",
                "password-check-word",
                "password-generator",
                "word-hints",
                "random-source"
            ]
        );
        assert_eq!(
            wallet(None).ids(),
            [
                "bip39-words",
                "wallet-hashes",
                "bip39-seed",
                "bip32",
                "addresses",
                "address-search",
                "wallet-check",
                "word-wishes",
                "word-hints",
                "random-source"
            ]
        );
        // Without an Argon2 check, the core says Argon2 was not run.
        let mut core = core(None);
        assert_eq!(core.ids()[1], "argon2");
        let report = core.run_quietly(Tier::Startup);
        assert!(report.passed(), "{:?}", report.first_failure());
        assert_eq!(report.results()[1].outcome().name(), "notRun");
    }

    #[test]
    fn every_set_passes_at_startup() {
        for (name, mut set) in [
            ("repair", repair()),
            ("passwords", passwords(None)),
            ("wallet", wallet(None)),
            ("native", native(None)),
        ] {
            let report = set.run_quietly(Tier::Startup);
            assert!(report.passed(), "{name}: {:?}", report.first_failure());
        }
    }

    /// The startup set of the command-line tool stays within its budget: well under half a second
    /// in a release build, where it takes a few tens of milliseconds. A debug build runs the hashes
    /// and the curve arithmetic unoptimized, many times slower, so its bound is generous. Run
    /// `cargo test --release --lib the_startup_set_stays_within_its_budget -- --nocapture` to see
    /// the time of each check.
    /// Runs `set` at `tier` and prints the time of each check and of all, under `name`.
    fn timed(
        mut set: SelfCheck<'_>,
        tier: Tier,
        name: &str,
    ) -> (super::super::SelfCheckReport, std::time::Duration) {
        use std::time::Instant;
        let started = Instant::now();
        let check_started = std::cell::Cell::new(started);
        let mut times = Vec::new();
        let report = set.run(
            tier,
            &mut |_, _| check_started.set(Instant::now()),
            &mut |result| times.push((result.id(), check_started.get().elapsed())),
        );
        let total = started.elapsed();
        times.push((name, total));
        for (id, time) in &times {
            eprintln!("{id:<20} {:>9.2} ms", time.as_secs_f64() * 1e3);
        }
        (report, total)
    }

    #[test]
    fn the_startup_set_stays_within_its_budget() {
        use std::time::Duration;
        let budget = if cfg!(debug_assertions) {
            Duration::from_secs(30)
        } else {
            Duration::from_millis(500)
        };
        let (report, total) = timed(native(None), Tier::Startup, "startup set");
        assert!(report.passed(), "{:?}", report.first_failure());
        assert!(total < budget, "the startup set took {total:?}");
    }

    /// The full self-test of the command-line tool, with the operating system's generator. It
    /// scans every Unicode scalar value and runs Argon2 at 256 MiB, seconds in a debug build, so it
    /// runs on request: `cargo test --release --lib -- --ignored the_full_set_passes --nocapture`.
    #[test]
    #[ignore = "the whole full self-test: seconds and 256 MiB"]
    fn the_full_set_passes_with_the_system_generator() {
        let mut system = |bytes: &mut [u8]| {
            getrandom::fill(bytes)
                .map_err(|_| crate::MhfeError::RandomFailed("getrandom failed".to_owned()))
        };
        let (report, _) = timed(native(Some(&mut system)), Tier::Full, "full set");
        assert!(report.passed(), "{:?}", report.first_failure());
        assert!(report
            .results()
            .iter()
            .all(|result| !matches!(result.outcome(), ComponentOutcome::NotRun(_))));
    }

    /// The labels and details a page shows name no coin, at either tier.
    #[test]
    fn labels_name_no_coin() {
        let set = native(None);
        let report_labels: Vec<&str> = set.checks.iter().map(|check| check.label()).collect();
        for label in report_labels {
            for coin in crate::wallet::Coin::ALL {
                let name = coin.name().to_lowercase();
                let first = name.split(' ').next().unwrap_or_default();
                assert!(!label.to_lowercase().contains(first), "{label}");
            }
        }
    }
}
