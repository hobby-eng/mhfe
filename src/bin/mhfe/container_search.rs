//! The search for missing words of a container phrase when its repair words are lost, at a
//! terminal: the questions around the library's [`ContainerSearch`]. Every word the BIP39 checksum
//! allows in place of a word marked `?` makes a candidate, and what the person knows tells the
//! right one. They say first what they know: an address or the fingerprint of the container's own
//! wallet, compared without any recovery; of their wallet, the original seed phrase's, which
//! recovers every candidate with the password; the original seed phrase's passphrase alone, for
//! its own checks; or nothing, which leaves the built-in check of a 12- to 21-word original seed
//! phrase. For a wallet they are then asked whether a BIP39 passphrase is used with the container
//! phrase or with the original seed phrase, each named. A recovery of a candidate takes the full
//! time, so those searches look for one missing word and say how long they take first. After a
//! refusal or a search that finds nothing, the question comes again: the container phrase is
//! typed once.

use std::fmt::Write as _;
use std::io::IsTerminal;

use anstream::{eprint, eprintln};
use mhfe::engine::NativeEngine;
use mhfe::memory::LockedText;
use mhfe::search::{ContainerSearch, Found, DECOY_SCAN_GAP, MAX_MISSING_FOR_WALLET};
use mhfe::wallet::SearchLimits;
use mhfe::{MhfeError, Password, Reference, WorkFactor};
use zeroize::Zeroizing;

use crate::check::{self, WalletReference, CONTAINER_PHRASE, ORIGINAL_SEED_PHRASE};
use crate::choice::{self, Answer, Question};
use crate::container_repair::{Reviewed, SearchContext};
use crate::exit::{refused, Failure};
use crate::readme;
use crate::settings;
use crate::style::{self, paint, GOOD, HEADING, STRONG};
use crate::terminal::{self, Input, Progress};

/// What the person knows, to tell the right candidate.
#[derive(Clone, Copy)]
enum Known {
    /// An address or the fingerprint of the container's own wallet.
    ContainerWallet,
    /// An address or the fingerprint of the original seed phrase's wallet.
    OriginalWallet,
    /// The BIP39 passphrase of the original seed phrase alone.
    OriginalPassphrase,
    Nothing,
    TypeAgain,
}

/// Where a search leads.
enum Next {
    /// The container phrase found, to be read.
    Use(Reviewed),
    /// Back to the question of what is known, after a refusal or nothing found.
    AskAgain,
    /// Back to the container phrase.
    TypeAgain,
}

/// Searches for the words of `written` typed as `?`, without its repair words, asking what the
/// person knows again until a container phrase is found and used. `None` asks for the container
/// phrase again.
pub fn search_missing(
    input: &mut Input,
    written: &str,
    context: SearchContext,
) -> Result<Option<Reviewed>, Failure> {
    let search = match ContainerSearch::new(written) {
        Ok(search) => search,
        Err(error) => {
            style::retry(refused(&error, ""));
            return Ok(None);
        }
    };
    loop {
        let next = match ask_what_is_known(input, &search)? {
            Known::TypeAgain => Next::TypeAgain,
            Known::ContainerWallet => with_container_wallet(input, &search, context)?,
            Known::OriginalWallet => with_original_wallet(input, &search, context)?,
            Known::OriginalPassphrase => with_own_checks(input, &search, context, true)?,
            Known::Nothing => with_own_checks(input, &search, context, false)?,
        };
        match next {
            Next::Use(reviewed) => return Ok(Some(reviewed)),
            Next::TypeAgain => return Ok(None),
            Next::AskAgain => continue,
        }
    }
}

/// What can tell the candidates apart, which the answers offer: the container's own wallet
/// always; with one missing word the original seed phrase's wallet too, and in a 24-word
/// container, which carries the built-in check or a phrase with the phrase + passphrase check,
/// the original seed phrase's own checks.
#[derive(Clone, Copy)]
struct Offered {
    original_wallet: bool,
    own_checks: bool,
}

impl Offered {
    fn of(search: &ContainerSearch) -> Self {
        Self {
            original_wallet: search.offers_wallet_search(),
            own_checks: search.offers_own_checks(),
        }
    }
}

fn ask_what_is_known(input: &mut Input, search: &ContainerSearch) -> Result<Known, Failure> {
    let candidates = format!(
        "MHFE tries every word the checksum allows: {} candidates.",
        search.count()
    );
    let mut explanation = vec![candidates.as_str(), A_WALLET_EXPLAINED];
    if !search.offers_wallet_search() {
        explanation.extend(TWO_MISSING_EXPLAINED);
    } else if !search.offers_own_checks() {
        explanation.push(NO_OWN_CHECK_EXPLAINED);
    }
    let (kinds, answers) = what_is_known_answers(Offered::of(search));
    let question = Question {
        text: "No repair words: what do you know?",
        explanation: &explanation,
        more: Some(readme::REPAIR),
        record: None,
    };
    Ok(kinds[input.choose_here(&question, &answers)?])
}

/// The answers of what is known, as far as they are `offered`.
fn what_is_known_answers(offered: Offered) -> (Vec<Known>, Vec<Answer>) {
    let mut known = vec![(
        Known::ContainerWallet,
        Answer::new(
            "The container's own wallet",
            "an address or fingerprint; fast",
        ),
    )];
    if offered.original_wallet {
        known.push((
            Known::OriginalWallet,
            Answer::new(
                "Your wallet (original seed phrase)",
                "an address or fingerprint; slow",
            ),
        ));
    }
    if offered.own_checks {
        known.push((
            Known::OriginalPassphrase,
            Answer::new(
                "The original seed phrase's passphrase",
                "checked by the phrase; slow",
            ),
        ));
        known.push((
            Known::Nothing,
            Answer::new("Nothing", "12- to 21-word phrases; slow"),
        ));
    }
    known.push((
        Known::TypeAgain,
        Answer::new("Type the container phrase again", "no search"),
    ));
    known.into_iter().unzip()
}

/// Said above the answers: what a wallet is known by.
const A_WALLET_EXPLAINED: &str =
    "A wallet is known by one of its addresses or its master key fingerprint.";

/// Compares every candidate with the container's own wallet, telling how far it has come on a
/// line of its own, rewritten in place at a terminal.
fn compare_with_decoy(
    search: &ContainerSearch,
    reference: &Reference<'_>,
    scan_gap: u32,
) -> Result<Option<Found>, Failure> {
    style::hint(&format!(
        "Comparing {} candidates with the container's own wallet.",
        search.count()
    ));
    let on_terminal = std::io::stderr().is_terminal();
    let found = search.search_decoy(reference, scan_gap, &mut |done, count| {
        if on_terminal {
            // Carriage return and erase to the end of the line: the count is redrawn in place.
            eprint!("\r  Compared {done} of {count}\x1b[K");
        }
        Ok(())
    })?;
    if on_terminal {
        eprintln!();
    }
    Ok(found)
}

/// Asks how far to search an address of the container's own wallet for two missing words.
fn ask_scan_gap(input: &mut Input) -> Result<u32, Failure> {
    let answers = gap_answers();
    let question = Question {
        text: "How far does the wallet go?",
        explanation: &GAP_EXPLAINED,
        more: Some(readme::REPAIR),
        record: None,
    };
    let chosen = input.choose_here(&question, &answers)?;
    let gap = match SCAN_GAPS.get(chosen) {
        Some(&gap) => gap,
        None => read_own_gap(input)?,
    };
    choice::record(
        "Scan gap",
        &format!("the first {gap} addresses of each chain"),
    );
    Ok(gap)
}

/// Room for one found word in its line: "word 24: ", a BIP39 word of at most 8 letters, the
/// colour codes around it and ", ", so that the line never grows past its buffer.
const FOUND_WORD_BYTES: usize = 64;

/// The gaps offered, in the order of [`gap_answers`]; the last answer types any other, as
/// `--scan-gap` gives one.
const SCAN_GAPS: [u32; 3] = [DECOY_SCAN_GAP, 100, 500];

/// One answer for each of [`SCAN_GAPS`], with how much longer it takes than the usual gap, and
/// one to type another number.
fn gap_answers() -> Vec<Answer> {
    let mut answers: Vec<Answer> = SCAN_GAPS
        .iter()
        .map(|&gap| {
            let cost = if gap == DECOY_SCAN_GAP {
                "the usual gap of a wallet".to_owned()
            } else {
                format!("about {} times as long", gap / DECOY_SCAN_GAP)
            };
            Answer::new(format!("The first {gap} addresses"), cost)
        })
        .collect();
    answers.push(Answer::new("Another number", "type how many"));
    answers
}

/// The most addresses of each chain a gap may have.
const MOST_SCAN_GAP: u32 = SearchLimits::MOST;

/// Reads a gap of the person's own, again until it is a whole number from 1 to 2^31.
fn read_own_gap(input: &mut Input) -> Result<u32, Failure> {
    loop {
        let typed = input.visible("Addresses of each chain: ")?;
        match typed.trim().parse::<u32>() {
            Ok(gap) if (1..=MOST_SCAN_GAP).contains(&gap) => return Ok(gap),
            _ => {
                style::retry(format!(
                    "Type a whole number of addresses from 1 to {MOST_SCAN_GAP}."
                ));
            }
        }
    }
}

/// Said above the gaps: what they cost.
const GAP_EXPLAINED: [&str; 2] = [
    "Receiving and change addresses of the first account. Each candidate",
    "has its own, so a wider search takes longer.",
];

/// Said above the answers when two words are missing.
const TWO_MISSING_EXPLAINED: [&str; 2] = [
    "Two words are missing: only a fingerprint or an address of the",
    "container's own wallet finds them, without the password.",
];
/// Said above the answers for a container as long as its original seed phrase.
const NO_OWN_CHECK_EXPLAINED: &str =
    "A container as long as its seed phrase has no check of its own.";

/// An address or the fingerprint of the container's own wallet: no recovery, so that it needs no
/// password; with a BIP39 passphrase only if the person says one is used with the container
/// phrase.
fn with_container_wallet(
    input: &mut Input,
    search: &ContainerSearch,
    context: SearchContext,
) -> Result<Next, Failure> {
    let reference = WalletReference::read_address_or_fingerprint(input)?;
    // How far an address is searched for two missing words: as given, or as asked; a fingerprint
    // or one missing word needs no gap.
    let two_missing = search.missing().len() > MAX_MISSING_FOR_WALLET;
    let scan_gap = match context.scan_gap {
        Some(gap) => gap,
        None if two_missing && reference.is_address() => ask_scan_gap(input)?,
        None => DECOY_SCAN_GAP,
    };
    let limits = match search.decoy_address_limits(scan_gap) {
        Ok(limits) => limits,
        Err(error) => {
            style::retry(refused(&error, ""));
            return Ok(Next::AskAgain);
        }
    };
    reference.show_search(limits);
    let passphrase = check::ask_passphrase(input, context.operation, CONTAINER_PHRASE)?;
    eprintln!();
    let found = compare_with_decoy(search, &reference.reference_with(&passphrase), scan_gap)?;
    match found {
        Some(found) => {
            // Listed among the matches of a check: what the container phrase was found by.
            let at = found
                .outcome
                .path()
                .map(|path| format!(" at {path}"))
                .unwrap_or_default();
            let found_by = format!("the container's own wallet: {}{at}", reference.shown());
            use_found(
                input,
                found,
                None,
                "with the container's own wallet",
                Some(found_by),
            )
        }
        None => {
            style::retry(NOT_FOUND_IN_CONTAINER_WALLET);
            Ok(Next::AskAgain)
        }
    }
}

/// An address or the fingerprint of the original seed phrase's wallet: every candidate is
/// recovered with the password and compared, a full recovery each, for one missing word.
fn with_original_wallet(
    input: &mut Input,
    search: &ContainerSearch,
    context: SearchContext,
) -> Result<Next, Failure> {
    let reference = WalletReference::read_address_or_fingerprint(input)?;
    reference.show_search(SearchLimits::default());
    let passphrase = check::ask_passphrase(input, context.operation, ORIGINAL_SEED_PHRASE)?;
    let reference = reference.reference_with(&passphrase);
    search_by_recoveries(input, search, context, &reference, SearchWords::WITH_WALLET)
}

/// The original seed phrase's own checks, with no fingerprint or address: its built-in check,
/// and with the BIP39 passphrase of its wallet, `with_passphrase`, the phrase + passphrase check.
fn with_own_checks(
    input: &mut Input,
    search: &ContainerSearch,
    context: SearchContext,
    with_passphrase: bool,
) -> Result<Next, Failure> {
    let passphrase = if with_passphrase {
        check::read_passphrase_named(input, context.operation, ORIGINAL_SEED_PHRASE)?
    } else {
        LockedText::copy_of("")
    };
    let checked = Reference::own_checks(&passphrase);
    search_by_recoveries(input, search, context, &checked, SearchWords::BY_OWN_CHECKS)
}

/// What a search by recoveries says it found the words by, and when it found none.
struct SearchWords {
    by: &'static str,
    none: &'static str,
}

impl SearchWords {
    const WITH_WALLET: Self = Self {
        by: "with your wallet",
        none: NOT_FOUND_WITH_REFERENCE,
    };
    const BY_OWN_CHECKS: Self = Self {
        by: "by the original seed phrase's own check",
        none: NOT_FOUND_BY_OWN_CHECKS,
    };
}

/// Recovers every candidate with the password until one matches `reference`, an address or
/// fingerprint of the wallet or the original seed phrase's own checks: the settings, the time it
/// takes and the password are asked first, a full recovery a candidate.
fn search_by_recoveries(
    input: &mut Input,
    search: &ContainerSearch,
    context: SearchContext,
    reference: &Reference<'_>,
    said: SearchWords,
) -> Result<Next, Failure> {
    let work = context.work(input)?;
    if !starts_long_search(input, search, work)? {
        return Ok(Next::AskAgain);
    }
    let password = terminal::read_password(input, context.operation)?;
    let found = run_long(search, work, |mhfe, progress| {
        search.search_wallet(mhfe, &password, reference, progress)
    })?;
    match found {
        Some(found) => use_found(input, found, Some(password), said.by, None),
        None => {
            style::retry(said.none);
            Ok(Next::AskAgain)
        }
    }
}

const NOT_FOUND_IN_CONTAINER_WALLET: &str =
    "The container's own wallet does not match: the address \
     or fingerprint, the passphrase or the scan gap is not that wallet's, or another word of the \
     container phrase is wrong.";
const NOT_FOUND_WITH_REFERENCE: &str = "No candidate matches: the fingerprint or address, its \
     passphrase, the password or a setting is wrong.";
const NOT_FOUND_BY_OWN_CHECKS: &str = "No candidate passes a check of the original seed phrase: \
     a 24-word one made without the phrase + passphrase check has none, or the passphrase, the \
     password or a setting is wrong. Try a fingerprint or an address.";

fn start_answers() -> [Answer; 2] {
    [
        Answer::new("Start the search", "Ctrl+C stops it at any time"),
        Answer::new("Not now", "back to what you know of the wallet"),
    ]
}

/// Says how long recovering every candidate takes at these settings and asks to start.
fn starts_long_search(
    input: &mut Input,
    search: &ContainerSearch,
    work: WorkFactor,
) -> Result<bool, Failure> {
    let (low, high) = work.estimated_seconds();
    let count = search.count() as u64;
    let took = format!(
        "{} candidates, each a full recovery: about {} at these settings.",
        search.count(),
        settings::time_range(low * count, high * count)
    );
    eprintln!();
    style::warn_here(&took, "");
    let answers = start_answers();
    let question = Question {
        text: "Start the search?",
        explanation: &[],
        more: None,
        record: None,
    };
    Ok(input.choose_here(&question, &answers)? == 0)
}

/// Runs a search that recovers every candidate, one progress line a candidate.
fn run_long(
    search: &ContainerSearch,
    work: WorkFactor,
    run: impl FnOnce(
        &mut mhfe::Mhfe<NativeEngine>,
        &mut dyn FnMut(usize, usize, u32, u32) -> Result<(), MhfeError>,
    ) -> Result<Option<Found>, MhfeError>,
) -> Result<Option<Found>, Failure> {
    let mut mhfe = settings::reserve_memory(work)?;
    let mut progress = Progress::start_as("Searching");
    style::hint(&format!("{} candidates, one line each.", search.count()));
    let mut current = 0;
    let found = run(&mut mhfe, &mut |candidate, _, round, rounds| {
        if candidate != current {
            if current != 0 {
                progress.next_operation();
            }
            current = candidate;
        }
        progress.round_starts(round, rounds);
        Ok(())
    })?;
    progress.finish();
    Ok(found)
}

fn found_answers() -> [Answer; 2] {
    [
        Answer::new("Use it", "and write the found words on your copy"),
        Answer::new("Type the container phrase again", "the search is not used"),
    ]
}

/// Shows the container phrase found, each missing word as found, and asks before it is used.
fn use_found(
    input: &mut Input,
    found: Found,
    password: Option<Password>,
    how: &str,
    found_by: Option<String>,
) -> Result<Next, Failure> {
    eprintln!();
    eprintln!(
        "{}",
        paint(
            HEADING,
            format!(
                "Found container phrase, {} words",
                found.container.split(' ').count()
            )
        )
    );
    for line in style::boxed_words(&found.container) {
        eprintln!("{}", *line);
    }
    // Written into one buffer reserved at its final size and wiped when dropped: the words are
    // container words (AUD-017-SEC001).
    let mut places = Zeroizing::new(String::with_capacity(found.words.len() * FOUND_WORD_BYTES));
    for (index, (position, word)) in found.words.iter().enumerate() {
        if index > 0 {
            places.push_str(", ");
        }
        // Writing into a String cannot fail.
        let _ = write!(places, "word {position}: {STRONG}{word}{STRONG:#}");
    }
    // Not style::ok, which keeps its line for the summary on the main screen: the words found
    // stay on this private screen.
    eprintln!("{} Found {}, {how}.", paint(GOOD, style::TICK), *places);
    let answers = found_answers();
    let question = Question {
        text: "Use the found container phrase?",
        explanation: &[],
        more: None,
        record: None,
    };
    if input.choose_here(&question, &answers)? != 0 {
        return Ok(Next::TypeAgain);
    }
    let positions: Vec<String> = found
        .words
        .iter()
        .map(|(position, _)| position.to_string())
        .collect();
    let which = match positions.as_slice() {
        [one] => format!("word {one}"),
        many => format!("words {}", style::and_list(many)),
    };
    choice::record(
        "Search",
        how.trim_start_matches("with ").trim_start_matches("by "),
    );
    Ok(Next::Use(Reviewed {
        words: LockedText::copy_of(&found.container),
        repaired: Some(format!(
            "{which} of the container phrase, found by a search"
        )),
        password,
        found_by,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_messages_and_questions_fit() {
        assert!(choice::fits(&[
            "MHFE tries every word the checksum allows: 16384 candidates."
        ]));
        assert!(choice::fits(&TWO_MISSING_EXPLAINED));
        assert!(choice::fits(&[NO_OWN_CHECK_EXPLAINED]));
    }

    /// No note of a list here is cut with "…".
    #[test]
    fn the_lists_show_whole() {
        for original_wallet in [true, false] {
            for own_checks in [true, false] {
                let offered = Offered {
                    original_wallet,
                    own_checks,
                };
                assert!(choice::answers_fit(&what_is_known_answers(offered).1));
            }
        }
        assert!(choice::fits(&[A_WALLET_EXPLAINED]));
        assert!(choice::answers_fit(&gap_answers()));
        assert!(choice::fits(&GAP_EXPLAINED));
        assert!(choice::answers_fit(&start_answers()));
        assert!(choice::answers_fit(&found_answers()));
    }
}
