//! `mhfe check`: rehearses a recovery and reports only "matches", "does not match" or "not
//! verified".
//!
//! Nothing of the recovered phrase is shown, and a wrong password gives no hint of how close
//! it was. The strong reference is a receiving address of the wallet; the master key fingerprint
//! is a quick, weaker check; the built-in check of a short original confirms only that the
//! password recovers a consistent phrase.

use anstream::eprintln;
use clap::Args;
use mhfe::memory::LockedText;
use mhfe::wallet::{Coin, DerivationPath, SearchLimits};
use mhfe::wallet_check::{self, WALLET_CHECK_BITS};
use mhfe::{
    CheckEvidence, CheckOutcome, ContainerFacts, PassedCheck, Password, PhraseLength,
    RecoveredForCheck, Reference, ReferenceTarget, WordCount, WorkFactor,
    BUILT_IN_CHECK_WORD_COUNTS, WORD_COUNTS,
};

use crate::choice::{Answer, Question};
use crate::container_repair::{self, RepairOption};
use crate::exit::{Failure, NOT_VERIFIED, NO_MATCH, SUCCESS};
use crate::flow::Flow;
use crate::phrase_length;
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT};
use crate::terminal::{self, Input, Progress};

mod passphrase;
mod wallet_reference;

pub use passphrase::{
    ask_passphrase, ask_passphrase_explained, passphrase_screen, read_passphrase_named,
    read_passphrase_of, source_check_why, PassphraseUsedOption, CONTAINER_PHRASE,
    ORIGINAL_SEED_PHRASE,
};
use passphrase::{read_check_passphrase, read_own_checks_passphrase};
pub use wallet_reference::{wallet_answers, WalletReference};

#[derive(Args)]
#[command(group = clap::ArgGroup::new("reference").args(["address", "fingerprint", "words"]))]
pub struct Options {
    #[command(flatten)]
    settings: Settings,

    #[command(flatten)]
    repair: RepairOption,

    /// Compare with a receiving address (strong check)
    #[arg(long, long_help = address_help())]
    address: bool,

    /// With --address: the coin (a script's default: bitcoin)
    #[arg(long, value_name = "COIN", requires = "address", long_help = coin_help())]
    coin: Option<Coin>,

    /// Compare with the master key fingerprint (quick, weaker)
    #[arg(long, long_help = fingerprint_help())]
    fingerprint: bool,

    #[arg(
        long,
        value_name = "N",
        value_parser = phrase_length::parse,
        help = format!("Built-in check of a {} seed phrase, or auto", phrase_length::short_range_words()),
        long_help = words_help()
    )]
    words: Option<PhraseLength>,

    /// With --address: look only at this derivation path
    #[arg(long, value_name = "PATH", requires = "address", long_help = path_help())]
    path: Option<DerivationPath>,

    #[command(flatten)]
    passphrase_used: PassphraseUsedOption,

    #[arg(long, help = style::STDIN_HELP, requires = "reference", long_help = stdin_help())]
    stdin: bool,
}

fn address_help() -> String {
    let coins: Vec<&str> = Coin::ALL.iter().map(|coin| coin.name()).collect();
    let limits = SearchLimits::default();
    style::option_help(&[
        "Compare with a receiving address (strong check).",
        &format!(
            "Asks for the coin and a single-key receiving address of the wallet: {}. A Bitcoin \
             address may be legacy, nested SegWit, native SegWit or Taproot, also on testnet, \
             and a Zcash one transparent. It searches the first {} receiving and change \
             addresses of accounts 0 to {} on the standard paths of that address, which it \
             shows before the check.",
            style::or_list(&coins),
            limits.indexes(),
            limits.accounts() - 1
        ),
        "A match confirms the phrase, the wallet and its BIP39 passphrase together.",
    ])
}

fn coin_help() -> String {
    let coins: Vec<&str> = Coin::ALL.iter().map(|coin| coin.id()).collect();
    style::option_help(&[
        "With --address: the coin of the address; a script without it means bitcoin.",
        &format!(
            "One of {}. ethereum covers every EVM network, such as BNB Smart Chain, Polygon, \
             Avalanche C-Chain, Arbitrum, Optimism and Base. Without this option a person is \
             asked, and a script compares with a Bitcoin address: it says so, and refuses an \
             address of another coin with a pointer to --coin.",
            coins.join(", ")
        ),
    ])
}

fn fingerprint_help() -> String {
    style::option_help(&[
        "Compare with the master key fingerprint (quick, weaker).",
        "Asks for the BIP32 master key fingerprint, eight hexadecimal digits such as 73c5da0a, \
         which many wallets show. It has only 32 bits: a match is very likely right, but it is \
         a weaker proof than an address.",
    ])
}

fn words_help() -> String {
    style::option_help(&[
        &format!(
            "The container's built-in check, of a {} original seed phrase.",
            phrase_length::short_range_words()
        ),
        &format!(
            "N is the length of the original seed phrase: {}, or {} to detect it. A check that \
             passes at another length takes precedence and matches, and the tool says so; \
             several other lengths that pass leave it not verified. A match confirms the \
             password and the settings only, not the wallet or a BIP39 passphrase. A 24-word \
             original seed phrase and a container as long as its original seed phrase have no \
             built-in check; compare them with an address or the fingerprint. With {1}, the BIP39 \
             passphrase of the original seed phrase is asked too, which finds a 24-word phrase \
             drawn with the phrase + passphrase check of mhfe new; --passphrase-used answers \
             whether it has one.",
            phrase_length::short_lengths(),
            phrase_length::AUTO
        ),
    ])
}

fn path_help() -> String {
    style::option_help(&[
        "With --address: look only at this derivation path.",
        "A full path such as m/84'/0'/0'/0/5, for an address outside the standard search. \
         Only this one address is compared.",
    ])
}

fn stdin_help() -> String {
    style::stdin_help(
        Some("needs a reference option"),
        &[
            "Input: the container, the password, then with --address or --fingerprint the \
         reference and the BIP39 passphrase (an empty line if none), and with --words auto the \
         BIP39 passphrase of the original seed phrase (an empty line if none), one per line. With \
         --address, --coin names the coin of the address; without it the address is \
         Bitcoin's. Output: \"matches\" with exit code 0, \"does not match\" with exit code \
         3, or \"not verified\" with exit code 5, the reason on standard error.",
            container_repair::REPAIR_LINE,
        ],
    )
}

/// The one-line summary of the command: `-h`, the first line of `--help`, and its menu entry.
pub const SUMMARY: &str = "Rehearse a recovery without ever showing the phrase";

/// The top of `mhfe check --help`.
pub fn about() -> String {
    style::command_about(&[
        SUMMARY,
        "Runs the same 12 rounds as a recovery and compares the result with something you know \
         about the wallet: a receiving address, the master key fingerprint, or, for a 12- to \
         21-word original seed phrase, its built-in check. Without a reference option it offers a \
         list.",
    ])
}

/// The reference as typed, before it is read into its type.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Choice {
    Address,
    Fingerprint,
    BuiltInCheck(usize),
    /// The check of a phrase that `mhfe new` made with one (a draft), with the wallet's BIP39
    /// passphrase, which the check needs.
    WalletCheck,
    /// The original seed phrase's own checks with its length detected: the built-in check of the
    /// length that passes it, or with a BIP39 passphrase the phrase + passphrase check.
    OwnChecks,
}

fn examples() -> String {
    style::help_section(
        "Examples:",
        &[
            ("mhfe check", "Choose the reference from a list"),
            ("mhfe check --address", "Compare with a receiving address"),
            (
                "mhfe check --fingerprint",
                "Compare with the master key fingerprint",
            ),
            (
                "mhfe check --words 12",
                "Built-in check of a 12-word original seed phrase",
            ),
            (
                "mhfe check --address --path \"m/84'/0'/0'/0/5\"",
                "Compare with the address at this one path",
            ),
            (
                "mhfe check --fingerprint --pim 1 --mem 1",
                "The fingerprint, with the settings used for encryption",
            ),
            (
                "your-program | mhfe check --stdin --address --coin bitcoin",
                "A script: the answers from another program, one per line",
            ),
        ],
    )
}

/// The end of `mhfe check -h`.
pub fn help() -> String {
    examples()
}

/// The end of `mhfe check --help`.
pub fn long_help() -> String {
    let asks = style::help_section(
        "What it asks for:",
        &[
            ("Container", "shown while typed"),
            ("Password", "on a private screen"),
            (
                "Reference",
                "a receiving address, the fingerprint, or the word count",
            ),
            (
                "BIP39 passphrase",
                "on a private screen; Enter if the wallet has none, but the phrase + \
                 passphrase check needs one",
            ),
        ],
    );
    let note = style::help_note(
        "The check shows only whether the recovery matches, never any part of the phrase.",
    );
    format!("{asks}\n{}\n{note}", examples())
}

pub fn run(options: Options) -> Result<i32, Failure> {
    refuse_early(&options)?;
    let mut input = Input::new(options.stdin).reading_secrets()?;
    // At a terminal every step on a screen of its own, the summary at the end.
    let flow = Flow::start(&input, Operation::Check.title());
    let work = settings::choose(options.settings, &mut input, Operation::Check)?;

    let read = terminal::read_container(
        &mut input,
        Operation::Check.title(),
        options.repair.card(Operation::Check, work),
    )?;
    let container = read.facts;
    // Refused before the password is asked, as the check would refuse it.
    if let Some(length) = options.words {
        container.require_reference(&ReferenceTarget::Length(length).with(""))?;
    }
    // A search for missing words asked for the password already.
    let password = match read.password {
        Some(password) => password,
        None => terminal::read_password(&mut input, Operation::Check)?,
    };
    let choice = choose(&mut input, &options, &container)?;
    // The reference and passphrase are read before the long computation starts, so the user
    // can walk away while it runs.
    let given = GivenReference::read(&mut input, choice, &options)?;
    let reference = given.reference();
    let recovered = recover(work, &container, &password, &reference)?;
    let compared = compare(&mut input, &recovered, choice, &reference, &options)?;
    drop(recovered);
    // The result follows the summary on the main screen.
    flow.finish();
    report(&input, compared, read.found_by.as_deref())
}

/// Refuses options that cannot go together before anything is asked: only a short original
/// carries a built-in check, and `--passphrase-used` belongs to the original's own checks.
fn refuse_early(options: &Options) -> Result<(), Failure> {
    if let Some(PhraseLength::Words(words)) = options.words {
        mhfe::require_built_in_check_length(words)?;
    }
    refuse_misplaced_passphrase_used(options)
}

/// What to compare with: the reference that an option names, or else the person's answer.
fn choose(
    input: &mut Input,
    options: &Options,
    container: &ContainerFacts,
) -> Result<Choice, Failure> {
    Ok(
        match (options.address, options.fingerprint, options.words) {
            (true, _, _) => Choice::Address,
            (_, true, _) => Choice::Fingerprint,
            (_, _, Some(PhraseLength::Words(words))) => Choice::BuiltInCheck(words.get()),
            (_, _, Some(PhraseLength::Detect)) => Choice::OwnChecks,
            _ => ask_for_choice(input, container)?,
        },
    )
}

/// A reference as read, owning what its [`Reference`] borrows.
enum GivenReference {
    Wallet(WalletReference),
    BuiltInCheck(WordCount),
    WalletCheck(LockedText),
    OwnChecks(LockedText),
}

impl GivenReference {
    /// Reads the reference of `choice`, and the BIP39 passphrase it is compared with.
    fn read(input: &mut Input, choice: Choice, options: &Options) -> Result<Self, Failure> {
        Ok(match choice {
            Choice::Address | Choice::Fingerprint => Self::Wallet(WalletReference::read_given(
                input,
                matches!(choice, Choice::Fingerprint),
                options.coin,
                options.path.clone(),
                Operation::Check,
                None,
            )?),
            Choice::BuiltInCheck(words) => Self::BuiltInCheck(WordCount::new(words)?),
            // With the wallet's passphrase, which the library's rule requires.
            Choice::WalletCheck => {
                Self::WalletCheck(read_check_passphrase(input, Operation::Check)?)
            }
            Choice::OwnChecks => Self::OwnChecks(read_own_checks_passphrase(
                input,
                Operation::Check,
                options.passphrase_used.given(),
            )?),
        })
    }

    /// The library's reference.
    fn reference(&self) -> Reference<'_> {
        match self {
            Self::Wallet(wallet_reference) => wallet_reference.reference(),
            Self::BuiltInCheck(words) => Reference::BuiltInCheck { words: *words },
            Self::WalletCheck(passphrase) => Reference::WalletCheck { passphrase },
            Self::OwnChecks(passphrase) => Reference::own_checks(passphrase),
        }
    }
}

/// Recovers `container` with `password` at `work` for a comparison with `reference`. The work
/// area is released when it returns, before any further question.
fn recover(
    work: WorkFactor,
    container: &ContainerFacts,
    password: &Password,
    reference: &Reference<'_>,
) -> Result<RecoveredForCheck, Failure> {
    let mut mhfe = settings::reserve_memory(work)?;
    let mut progress = Progress::start();
    let recovered = mhfe.recover_for_check(
        container.words(),
        password,
        reference,
        &mut |round, rounds| {
            progress.round_starts(round, rounds);
            Ok(())
        },
    )?;
    progress.finish();
    Ok(recovered)
}

/// Compares `recovered` with `reference`. Detection that found no verified length asks for it: a
/// person states it, and a 24-word phrase is compared with the wallet on the same recovery.
fn compare(
    input: &mut Input,
    recovered: &RecoveredForCheck,
    choice: Choice,
    reference: &Reference<'_>,
    options: &Options,
) -> Result<Compared, Failure> {
    let compared = Compared::with(choice, reference, recovered)?;
    if choice == Choice::OwnChecks
        && compared.evidence.outcome == CheckOutcome::NotVerified
        && !input.is_script()
    {
        return ask_length_after_detection(
            input,
            recovered,
            &compared.evidence,
            options.coin,
            options.path.clone(),
        );
    }
    Ok(compared)
}

/// Reports the outcome: to a script the specification's words, to a person every check that
/// passed and what the outcome means. Returns the exit code of the outcome.
fn report(input: &Input, compared: Compared, found_by: Option<&str>) -> Result<i32, Failure> {
    let Compared {
        choice,
        evidence,
        with_passphrase,
    } = compared;
    let outcome = &evidence.outcome;

    eprintln!();
    if input.is_script() {
        // Scripts read exactly these words, the specification's.
        style::out(format_args!("{}", outcome.text()))?;
    }
    let shown = !input.is_script();
    let passed = || passed_lines(choice, &evidence, with_passphrase, found_by);
    match outcome {
        CheckOutcome::Matches { path } => {
            if shown {
                style::out(format_args!(
                    "{}",
                    paint(style::GOOD, format!("{} matches", style::TICK))
                ))?;
                // Every check that passed on a line of its own: the container phrase's checksum,
                // what found missing words, the reference compared with, and the original seed
                // phrase's own checks that the same recovery shows.
                for line in passed() {
                    style::out(format_args!("  {} {line}", paint(style::GOOD, style::TICK)))?;
                }
                // Which account and address of the wallet it is; a path given with --path is
                // shown too.
                if let Some(path) = path {
                    style::fact("Found at", paint(ACCENT, path));
                }
                if let (Choice::BuiltInCheck(stated), Some(found)) =
                    (choice, evidence.built_in_check)
                {
                    if found != stated {
                        style::warn(
                            &phrase_length::check_finds(found, stated),
                            &format!("{}.", phrase_length::MORE_RELIABLE),
                        );
                    }
                }
                if let Some(limit) = match_limit(choice) {
                    style::hint(limit);
                }
            }
            Ok(SUCCESS)
        }
        CheckOutcome::NotVerified => {
            if shown {
                style::out(format_args!("{}", paint(style::WARNING, "! not verified")))?;
                for line in passed() {
                    style::out(format_args!("  {} {line}", paint(style::GOOD, style::TICK)))?;
                }
            }
            style::hint(&not_verified_reason(choice, &evidence));
            style::more(readme::CHECK);
            Ok(NOT_VERIFIED)
        }
        CheckOutcome::DoesNotMatch => {
            if shown {
                style::out(format_args!("{}", paint(style::BAD, "✗ does not match")))?;
            }
            style::hint(no_match_reason(choice));
            style::more(readme::CHECK);
            Ok(NO_MATCH)
        }
    }
}

/// Why nothing matched, by what was compared.
fn no_match_reason(choice: Choice) -> &'static str {
    match choice {
        Choice::BuiltInCheck(_) => {
            "No length's built-in check passes: the password, a setting or the container is \
             probably wrong, or the phrase has 24 words."
        }
        Choice::WalletCheck => {
            "If the phrase was drawn with this check, the password, a setting or the passphrase \
             is wrong."
        }
        _ => "The password, a setting, the container, passphrase or reference is wrong.",
    }
}

/// Why the recovery is not verified, and what verifies it: several lengths that pass their
/// built-in checks, of which at most one is the phrase's, or a 24-word reading, which a wrong
/// password gives too and which only a wallet reference verifies.
fn not_verified_reason(choice: Choice, evidence: &CheckEvidence) -> String {
    if let [_, _, ..] = evidence.matching_lengths[..] {
        let stated = match choice {
            Choice::BuiltInCheck(words) => format!("The built-in check of {words} words fails. "),
            _ => String::new(),
        };
        return format!(
            "{stated}{} State the length (--words N) or compare with a receiving address \
             (--address).",
            several_lengths(&evidence.matching_lengths)
        );
    }
    match choice {
        Choice::WalletCheck => format!(
            "A wrong password passes the {WALLET_CHECK_BITS}-bit phrase + passphrase check about \
             once in {}: only a receiving address (--address) or the fingerprint proves the \
             wallet.",
            mhfe::grouped(wallet_check::WALLET_CHECK_ODDS)
        ),
        _ => format!(
            "No length of {} words passes its built-in check, so the recovery reads 24 words, as \
             it does for a wrong password: a receiving address (--address) or the fingerprint \
             tells them apart.",
            phrase_length::short_range()
        ),
    }
}

/// The lengths that pass their built-in checks, when several do: at most one is the phrase's.
fn several_lengths(lengths: &[usize]) -> String {
    format!(
        "The built-in checks of {} words pass, at most one of them for your phrase.",
        phrase_length::listed(lengths)
    )
}

/// Every check that passed, each on a line of its own: the container phrase's BIP39 checksum,
/// which every reading took; the wallet a search for missing words matched, `found_by`; the
/// wallet reference compared with, where it matched; and the original seed phrase's own checks
/// that the same recovery shows, only where they pass, as a phrase drawn without the phrase +
/// passphrase check fails it. Only an address or a fingerprint identifies the wallet; the built-in
/// check of a short original says nothing about the wallet or a BIP39 passphrase.
fn passed_lines(
    choice: Choice,
    evidence: &CheckEvidence,
    with_passphrase: bool,
    found_by: Option<&str>,
) -> Vec<String> {
    let passphrase = if with_passphrase {
        "with this BIP39 passphrase"
    } else {
        "without a BIP39 passphrase"
    };
    let mut lines = vec!["the container phrase passes its BIP39 checksum".to_owned()];
    lines.extend(found_by.map(ToOwned::to_owned));
    if evidence.outcome.matches() {
        lines.extend(match choice {
            Choice::Address => Some(format!("the receiving address of the wallet, {passphrase}")),
            Choice::Fingerprint => Some(format!(
                "the master key fingerprint of the wallet, {passphrase}"
            )),
            // The phrase's own checks are listed below, as the recovery shows them.
            _ => None,
        });
    }
    lines.extend(
        evidence
            .own_checks_passed()
            .iter()
            .map(|passed| match passed {
                PassedCheck::BuiltInCheck(words) => built_in_line(*words),
                PassedCheck::BuiltInChecks(lengths) => format!(
                    "the built-in checks of {} words",
                    phrase_length::listed(lengths)
                ),
                PassedCheck::WalletCheck => wallet_check_line(),
            }),
    );
    lines
}

fn built_in_line(words: usize) -> String {
    format!("the built-in check of a {words}-word original seed phrase")
}

fn wallet_check_line() -> String {
    format!("the phrase + passphrase check: its first {WALLET_CHECK_BITS} bits are zero")
}

/// The pass of the 16-bit source check as a fact, in the specification's words.
fn wallet_check_passes() -> String {
    format!("The 24-word reading passes the {WALLET_CHECK_BITS}-bit check.")
}

/// What a match of `choice` does not prove, said under the list.
fn match_limit(choice: Choice) -> Option<&'static str> {
    match choice {
        Choice::Address => None,
        Choice::Fingerprint => {
            Some("A fingerprint is a quick 32-bit check; an address (--address) is stronger.")
        }
        Choice::BuiltInCheck(_) | Choice::OwnChecks => {
            Some("It does not prove the wallet or its passphrase; an address (--address) does.")
        }
        Choice::WalletCheck => Some("It does not prove the wallet; an address (--address) does."),
    }
}

/// Asks what to compare with. A same-length container has no built-in check, so it is offered
/// only the address and the fingerprint.
fn ask_for_choice(input: &mut Input, container: &ContainerFacts) -> Result<Choice, Failure> {
    let mut answers = Vec::from(wallet_answers());
    // A check in the container, of a 12- to 21-word original, and one in the BIP39 seed of the
    // phrase and its passphrase: a phrase drawn so that a 16-bit hash of that seed is zero
    // (mhfe::wallet_check), which any program following the specification can make. The
    // passphrase is asked next.
    let lengths = container.built_in_check_lengths();
    if !lengths.is_empty() {
        answers.push(Answer::new(
            "The container's built-in check",
            "checks the password, not the wallet",
        ));
    }
    if container.offers_wallet_check() {
        answers.push(Answer::new(
            "The phrase + passphrase check",
            format!("{WALLET_CHECK_BITS}-bit hash of the BIP39 seed"),
        ));
    }
    let question = Question::new(
        "What should the recovered seed phrase be compared with?",
        "Compare",
    );
    match input.choose(&question, &answers)? {
        0 => Ok(Choice::Address),
        1 => Ok(Choice::Fingerprint),
        2 if !lengths.is_empty() => Ok(
            match phrase_length::ask(input, lengths, DETECTION_MISSES, "Original")? {
                PhraseLength::Words(words) => Choice::BuiltInCheck(words.get()),
                PhraseLength::Detect => Choice::OwnChecks,
            },
        ),
        _ => Ok(Choice::WalletCheck),
    }
}

/// What detection may not find in a check, beside its answer: a 24-word phrase has no built-in
/// check, and the phrase + passphrase check finds only one drawn with it.
pub const DETECTION_MISSES: &str = "24 words only by the passphrase check";

/// A check's comparison, as the result lists it.
struct Compared {
    choice: Choice,
    evidence: CheckEvidence,
    with_passphrase: bool,
}

impl Compared {
    fn with(
        choice: Choice,
        reference: &Reference<'_>,
        recovered: &RecoveredForCheck,
    ) -> Result<Self, Failure> {
        Ok(Self {
            choice,
            evidence: recovered.compare(reference)?,
            with_passphrase: reference.given_passphrase().is_some(),
        })
    }
}

/// Said over the question about the length when detection found none.
fn no_length_found() -> String {
    format!(
        "No length of {} words passes its built-in check.",
        phrase_length::short_range()
    )
}
/// Said under what detection found, over the question about the length.
const TWENTY_FOUR_COMPARED: &str =
    "A 24-word phrase is compared with an address or the fingerprint.";

/// After detection found no verified length, none or several, the person states it, and the same
/// recovery is compared again: a 12- to 21-word length with its built-in check, which detection
/// tried already, and a 24-word phrase with a receiving address or the fingerprint of the wallet.
/// What detection found, `detected`, is said over the question.
fn ask_length_after_detection(
    input: &mut Input,
    recovered: &RecoveredForCheck,
    detected: &CheckEvidence,
    coin: Option<Coin>,
    path: Option<DerivationPath>,
) -> Result<Compared, Failure> {
    let found = match &detected.matching_lengths[..] {
        [] => no_length_found(),
        lengths => several_lengths(lengths),
    };
    let mut explanation = vec![found.as_str()];
    let source_check = wallet_check_passes();
    if detected.wallet_check == Some(true) {
        explanation.push(&source_check);
    }
    explanation.push(TWENTY_FOUR_COMPARED);
    let words = phrase_length::ask_stated(input, &WORD_COUNTS, &explanation, "Original")?;
    if BUILT_IN_CHECK_WORD_COUNTS.contains(&words.get()) {
        let reference = Reference::BuiltInCheck { words };
        return Compared::with(Choice::BuiltInCheck(words.get()), &reference, recovered);
    }
    let question = Question::new("What should it be compared with?", "Compare");
    let fingerprint = input.choose(&question, &wallet_answers())? == 1;
    let wallet =
        WalletReference::read_given(input, fingerprint, coin, path, Operation::Check, None)?;
    let choice = if fingerprint {
        Choice::Fingerprint
    } else {
        Choice::Address
    };
    Compared::with(choice, &wallet.reference(), recovered)
}

/// `--passphrase-used` answers the question of the original seed phrase's own checks
/// (`--words auto`) at a terminal: a script gives that passphrase on its line, empty for none, and
/// the other references never ask it, so the option is refused there instead of ignored.
fn refuse_misplaced_passphrase_used(options: &Options) -> Result<(), Failure> {
    if options.passphrase_used.given().is_none() {
        return Ok(());
    }
    if options.words != Some(PhraseLength::Detect) {
        return Err(Failure::invalid_input(format!(
            "--passphrase-used belongs only to --words {}, the original seed phrase's own checks.",
            phrase_length::AUTO
        )));
    }
    if options.stdin {
        return Err(Failure::invalid_input(
            "--passphrase-used belongs only to a terminal: with --stdin the BIP39 passphrase of \
             the original seed phrase is a line of its own, empty if none.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(
        outcome: CheckOutcome,
        built_in_check: Option<usize>,
        matching_lengths: &[usize],
        wallet_check: Option<bool>,
    ) -> CheckEvidence {
        CheckEvidence {
            outcome,
            built_in_check,
            matching_lengths: matching_lengths.to_vec(),
            wallet_check,
        }
    }

    const MATCHES: CheckOutcome = CheckOutcome::Matches { path: None };

    #[test]
    fn only_a_wallet_reference_claims_the_wallet() {
        let built_in = passed_lines(
            Choice::BuiltInCheck(12),
            &evidence(MATCHES, Some(12), &[12], None),
            false,
            None,
        );
        assert!(
            built_in.iter().all(|line| !line.contains("wallet")),
            "{built_in:?}"
        );
        assert!(match_limit(Choice::BuiltInCheck(12))
            .unwrap()
            .contains("does not prove the wallet"));
        for choice in [Choice::Address, Choice::Fingerprint] {
            let matched = evidence(MATCHES, None, &[], None);
            assert!(passed_lines(choice, &matched, true, None)[1].contains("wallet"));
            // A reference that did not match is not listed among the checks that passed.
            let refused = evidence(CheckOutcome::DoesNotMatch, None, &[], None);
            assert_eq!(passed_lines(choice, &refused, true, None).len(), 1);
        }
    }

    /// Every check that passed is a line of its own, a check the same recovery shows besides
    /// included; a phrase + passphrase check that fails is not listed.
    #[test]
    fn every_passed_check_is_listed() {
        let found_by = "the container's own wallet: master key fingerprint e0f73b78";
        assert_eq!(
            passed_lines(
                Choice::Fingerprint,
                &evidence(MATCHES, Some(15), &[15], Some(true)),
                true,
                Some(found_by)
            ),
            [
                "the container phrase passes its BIP39 checksum",
                found_by,
                "the master key fingerprint of the wallet, with this BIP39 passphrase",
                "the built-in check of a 15-word original seed phrase",
                "the phrase + passphrase check: its first 16 bits are zero",
            ]
        );
        let failing = evidence(MATCHES, None, &[], Some(false));
        assert_eq!(
            passed_lines(Choice::Address, &failing, false, None).len(),
            2
        );
    }

    /// A recovery that is not verified lists what passed and says why it is not verified: the
    /// several lengths that pass, the stated one that fails, or the 24-word reading that a wrong
    /// password gives too (AUD-023-FUN002).
    #[test]
    fn a_recovery_that_is_not_verified_says_why() {
        let several = evidence(CheckOutcome::NotVerified, None, &[12, 21], Some(false));
        assert_eq!(
            passed_lines(Choice::OwnChecks, &several, false, None),
            [
                "the container phrase passes its BIP39 checksum",
                "the built-in checks of 12 and 21 words",
            ]
        );
        assert_eq!(
            not_verified_reason(Choice::OwnChecks, &several),
            "The built-in checks of 12 and 21 words pass, at most one of them for your phrase. \
             State the length (--words N) or compare with a receiving address (--address)."
        );
        assert!(not_verified_reason(Choice::BuiltInCheck(15), &several)
            .starts_with("The built-in check of 15 words fails. The built-in checks of 12 and 21"));
        let source_check = evidence(CheckOutcome::NotVerified, None, &[], Some(true));
        assert_eq!(
            passed_lines(Choice::WalletCheck, &source_check, true, None)[1],
            "the phrase + passphrase check: its first 16 bits are zero"
        );
        assert!(not_verified_reason(Choice::WalletCheck, &source_check)
            .contains("about once in 65,536"));
        assert!(not_verified_reason(Choice::OwnChecks, &source_check)
            .contains("as it does for a wrong password"));
    }
}
