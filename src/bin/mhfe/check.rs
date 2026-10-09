//! `mhfe check`: rehearses a recovery and reports only "matches" or "does not match".
//!
//! Nothing of the recovered phrase is shown, and a wrong password gives no hint of how close
//! it was. The strong reference is a receiving address of the wallet; the master key fingerprint
//! is a quick, weaker check; the built-in check of a short original confirms only that the
//! password recovers a consistent phrase.

use anstream::{eprintln, println};
use clap::Args;
use mhfe::memory::LockedText;
use mhfe::wallet::{
    fingerprint_text, parse_fingerprint, Address, AddressSearch, Coin, DerivationPath, SearchLimits,
};
use mhfe::wallet_check::{self, WALLET_CHECK_BITS};
use mhfe::{
    CheckEvidence, ContainerFacts, MhfeError, PhraseLength, RecoveredForCheck, Reference,
    ReferenceTarget, WordCount, BUILT_IN_CHECK_WORD_COUNTS, WORD_COUNTS,
};
use zeroize::Zeroizing;

use crate::choice::{self, Answer, Question};
use crate::container_repair::RepairOption;
use crate::exit::{refused, Failure, NO_MATCH, SUCCESS};
use crate::flow::Flow;
use crate::phrase_length;
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT};
use crate::terminal::{self, Input, PrivateScreen, Progress, Step};

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

    /// Built-in check of a 12- to 21-word seed phrase, or auto
    #[arg(long, value_name = "N", value_parser = phrase_length::parse, long_help = words_help())]
    words: Option<PhraseLength>,

    /// With --address: look only at this derivation path
    #[arg(long, value_name = "PATH", requires = "address", long_help = path_help())]
    path: Option<DerivationPath>,

    /// Read the answers from standard input (for scripts)
    #[arg(long, requires = "reference", long_help = stdin_help())]
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
        "The container's built-in check, of a 12- to 21-word original seed phrase.",
        "N is the length of the original seed phrase: 12, 15, 18 or 21, or auto to detect it. \
         A check that passes at another length takes precedence and matches, and the tool says \
         so. A match confirms the password and the settings only, not the wallet or a BIP39 \
         passphrase. A 24-word original seed phrase and a container as long as its original seed \
         phrase have no built-in check; compare them with an address or the fingerprint. With \
         auto, the BIP39 passphrase of the original seed phrase is asked too, which finds a \
         24-word phrase drawn with the phrase + passphrase check of mhfe new.",
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
    style::option_help(&[
        "Read the answers from standard input (for scripts); needs a reference option.",
        "Input: the container, the password, then with --address or --fingerprint the \
         reference and the BIP39 passphrase (an empty line if none), and with --words auto the \
         BIP39 passphrase of the original seed phrase (an empty line if none), one per line. With \
         --address, --coin names the coin of the address; without it the address is \
         Bitcoin's. Output: \"matches\" with exit code 0, or \"does not match\" with exit \
         code 3.",
    ])
}

/// The top of `mhfe check --help`.
pub fn about() -> String {
    style::command_about(&[
        "Rehearse a recovery without ever showing the phrase",
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

/// The coin of the address of a script that names none, as in v0.4.0 and v0.5.0, so that such a
/// script keeps working. It is never assumed silently: the summary names it, and the refusal of
/// an address of another coin says how to name that coin (AUD-010). A person is always asked, and
/// a page of the browser package must name the coin.
const SCRIPT_DEFAULT_COIN: Coin = Coin::Bitcoin;

pub fn run(options: Options) -> Result<i32, Failure> {
    // Refused before anything is asked: only a short original carries a built-in check.
    if let Some(PhraseLength::Words(words)) = options.words {
        mhfe::require_built_in_check_length(words)?;
    }
    let mut input = Input::new(options.stdin);
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
    let choice = match (options.address, options.fingerprint, options.words) {
        (true, _, _) => Choice::Address,
        (_, true, _) => Choice::Fingerprint,
        (_, _, Some(PhraseLength::Words(words))) => Choice::BuiltInCheck(words.get()),
        (_, _, Some(PhraseLength::Detect)) => Choice::OwnChecks,
        _ => ask_for_choice(&mut input, &container)?,
    };

    // The reference and passphrase are read before the long computation starts, so the user
    // can walk away while it runs.
    let wallet_reference: WalletReference;
    let check_passphrase: LockedText;
    let reference = match choice {
        Choice::Address | Choice::Fingerprint => {
            wallet_reference = WalletReference::read_given(
                &mut input,
                matches!(choice, Choice::Fingerprint),
                options.coin,
                options.path.clone(),
                Operation::Check,
                None,
            )?;
            wallet_reference.reference()
        }
        Choice::BuiltInCheck(words) => Reference::BuiltInCheck {
            words: WordCount::new(words)?,
        },
        Choice::WalletCheck => {
            // With the wallet's passphrase, which the library's rule requires.
            check_passphrase = read_check_passphrase(&mut input, Operation::Check)?;
            Reference::WalletCheck {
                passphrase: &check_passphrase,
            }
        }
        Choice::OwnChecks => {
            check_passphrase = read_own_checks_passphrase(&mut input, Operation::Check)?;
            Reference::own_checks(&check_passphrase)
        }
    };

    let mut mhfe = settings::reserve_memory(work)?;
    let mut progress = Progress::start();
    let recovered = mhfe.recover_for_check(
        container.words(),
        &password,
        &reference,
        &mut |round, rounds| {
            progress.round_starts(round, rounds);
            Ok(())
        },
    )?;
    progress.finish();
    // The work area is released before any further question.
    drop(mhfe);
    let mut compared = Compared::with(choice, &reference, &recovered)?;
    // Detection that found no length asks for it: a person states it, and a 24-word phrase is
    // compared with the wallet on the same recovery.
    if choice == Choice::OwnChecks && !compared.evidence.outcome.matches() && !input.is_script() {
        compared = ask_length_after_detection(&mut input, &recovered, options.coin, options.path)?;
    }
    drop(recovered);
    // The result follows the summary on the main screen.
    flow.finish();
    let Compared {
        choice,
        evidence,
        with_passphrase,
    } = compared;
    let outcome = &evidence.outcome;
    let matches = outcome.matches();

    eprintln!();
    if input.is_script() {
        // Scripts read exactly these words.
        println!("{}", if matches { "matches" } else { "does not match" });
    } else if matches {
        println!("{}", paint(style::GOOD, format!("{} matches", style::TICK)));
        // Every check that passed on a line of its own: the container phrase's checksum, what
        // found missing words, the reference compared with, and the original seed phrase's own
        // checks that the same recovery shows.
        for line in matched_lines(choice, &evidence, with_passphrase, read.found_by.as_deref()) {
            println!("  {} {line}", paint(style::GOOD, style::TICK));
        }
        // Which account and address of the wallet it is; a path given with --path is shown too.
        if let Some(path) = outcome.path() {
            style::fact("Found at", paint(ACCENT, path));
        }
        if let (Choice::BuiltInCheck(stated), Some(found)) = (choice, evidence.built_in_check) {
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
    } else {
        println!("{}", paint(style::BAD, "✗ does not match"));
    }
    if matches {
        Ok(SUCCESS)
    } else {
        style::hint(match choice {
            Choice::BuiltInCheck(_) => {
                "No length's built-in check passes: the password, a setting or the container is \
                 probably wrong, or the phrase has 24 words."
            }
            Choice::OwnChecks => {
                "The password, a setting or the container is wrong, or the phrase has 24 words \
                 without the phrase + passphrase check."
            }
            Choice::WalletCheck => {
                "If the phrase was drawn with this check, the password, a setting or the \
                 passphrase is wrong."
            }
            _ => "The password, a setting, the container, passphrase or reference is wrong.",
        });
        style::more(readme::CHECK);
        Ok(NO_MATCH)
    }
}

/// One 0x... address serves Ethereum and every EVM network, which the README lists.
const COIN_EXPLANATION: &[&str] =
    &["Ethereum also covers every EVM network, such as BNB Smart Chain."];

/// Asks which coin the address belongs to, in alphabetical order.
fn ask_for_coin(input: &mut Input) -> Result<Coin, Failure> {
    let answers: Vec<Answer> = Coin::ALL
        .iter()
        .map(|coin| Answer::new(coin.name(), coin.address_forms()))
        .collect();
    let question = Question {
        text: "Which coin is the address for?",
        explanation: COIN_EXPLANATION,
        more: None,
        record: Some("Coin"),
    };
    Ok(Coin::ALL[input.choose(&question, &answers)?])
}

fn show_search(address: &Address, path: Option<&DerivationPath>, limits: SearchLimits) {
    // Shown before the work starts too, so that a wrong address type can still be cancelled.
    let search = AddressSearch::new(address, path, limits);
    if let Some(kind) = search.type_description() {
        style::fact_before_work("Type", kind);
    }
    let text = if search.only_path() {
        format!("only {}", search.pattern())
    } else {
        format!(
            "{}, {} addresses",
            search.pattern(),
            style::grouped(search.addresses())
        )
    };
    style::fact_before_work("Search", text);
}

/// What a match shows, and its limit. Only an address or a fingerprint identifies the wallet;
/// the built-in check of a short original says nothing about the wallet or a BIP39 passphrase.
/// Every check of a match, each on a line of its own: the container phrase's BIP39 checksum, which
/// reading it took; the wallet a search for missing words matched, `found_by`; the reference
/// compared with; and the original seed phrase's own checks beside it, only where they pass, as a
/// phrase drawn without the phrase + passphrase check fails it.
fn matched_lines(
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
    lines.extend(match choice {
        Choice::Address => Some(format!("the receiving address of the wallet, {passphrase}")),
        Choice::Fingerprint => Some(format!(
            "the master key fingerprint of the wallet, {passphrase}"
        )),
        // The length whose check passed, which takes precedence over the one stated.
        Choice::BuiltInCheck(words) => {
            Some(built_in_line(evidence.built_in_check.unwrap_or(words)))
        }
        Choice::WalletCheck => Some(wallet_check_line()),
        // The phrase's own checks are listed below, as the recovery shows them.
        Choice::OwnChecks => None,
    });
    if let Some(words) = evidence.built_in_check {
        if !matches!(choice, Choice::BuiltInCheck(_)) {
            lines.push(built_in_line(words));
        }
    }
    if evidence.wallet_check == Some(true) && !matches!(choice, Choice::WalletCheck) {
        lines.push(wallet_check_line());
    }
    lines
}

fn built_in_line(words: usize) -> String {
    format!("the built-in check of a {words}-word original seed phrase")
}

fn wallet_check_line() -> String {
    format!("the phrase + passphrase check: its first {WALLET_CHECK_BITS} bits are zero")
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
            "16-bit hash of the BIP39 seed",
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

/// A reference of the wallet that the owner typed, a receiving address or the master key
/// fingerprint, with the wallet's BIP39 passphrase: what a check compares a recovery with, and what
/// confirms a recovery without a built-in check before it is encrypted again.
pub struct WalletReference {
    /// An address or a fingerprint.
    target: ReferenceTarget,
    passphrase: LockedText,
    /// What a search's reference was typed as, such as "master key fingerprint e0f73b78".
    shown: String,
}

/// What was typed for a search's reference, before an address's coin is known.
enum Typed {
    Fingerprint([u8; 4]),
    /// Not yet read as an address: wiped when dropped, as it may be anything typed.
    Address(Zeroizing<String>),
}

impl WalletReference {
    /// Reads a receiving address, of a coin asked for, or with `fingerprint` the master key
    /// fingerprint, of a wallet whose BIP39 passphrase the person has said it has or has not:
    /// only a wallet with one is then asked for it, on the private screen of `operation`, and it
    /// may not be empty.
    pub fn read_of_wallet(
        input: &mut Input,
        fingerprint: bool,
        operation: Operation,
        wallet_has_passphrase: bool,
    ) -> Result<Self, Failure> {
        Self::read_given(
            input,
            fingerprint,
            None,
            None,
            operation,
            Some(wallet_has_passphrase),
        )
    }

    /// Reads a reference for a search for missing words: one answer, "Address or master key
    /// fingerprint", eight hex digits being a fingerprint and anything else an address, whose coin
    /// is then asked. No passphrase is read: the search asks whose it would be.
    pub fn read_address_or_fingerprint(input: &mut Input) -> Result<Self, Failure> {
        // Nothing typed here is recorded before it is read as a fingerprint, or as an address of
        // the coin asked next, so that a seed phrase typed into the wrong field never reaches the
        // summary on the main screen (AUD-015-SEC001).
        let typed = read_public(input, "Address or master key fingerprint: ", None, |text| {
            let text = text.trim();
            if text.is_empty() {
                return Err(MhfeError::InvalidAddress("nothing was typed".to_owned()));
            }
            // An address and a fingerprint are one word; several words read as a seed phrase.
            if text.split_whitespace().nth(1).is_some() {
                return Err(MhfeError::InvalidAddress(
                    "an address or a fingerprint is one word, without spaces".to_owned(),
                ));
            }
            // No address of any coin has eight hex digits alone.
            Ok(match parse_fingerprint(text) {
                Ok(fingerprint) => Typed::Fingerprint(fingerprint),
                Err(_) => Typed::Address(Zeroizing::new(text.to_owned())),
            })
        })?;
        let (target, shown) = match typed {
            Typed::Fingerprint(fingerprint) => (
                ReferenceTarget::Fingerprint(fingerprint),
                format!("master key fingerprint {}", fingerprint_text(fingerprint)),
            ),
            Typed::Address(text) => {
                let coin = ask_for_coin(input)?;
                let (address, text) = match Address::parse(coin, &text) {
                    Ok(address) => (address, text.trim().to_owned()),
                    // Asked again with the coin known, which states the forms it takes.
                    Err(_) => read_public(
                        input,
                        &format!("Receiving or change address ({}): ", coin.address_forms()),
                        None,
                        |text| Ok((Address::parse(coin, text)?, text.trim().to_owned())),
                    )?,
                };
                let target = ReferenceTarget::Address {
                    address,
                    path: None,
                };
                (target, format!("address {text}"))
            }
        };
        // Only now, read as what the field asks for.
        choice::record("Reference", &shown);
        Ok(Self {
            target,
            passphrase: LockedText::copy_of(""),
            shown,
        })
    }

    /// What this reference was typed as, such as "address 3FWJ…" or "master key fingerprint
    /// e0f73b78"; empty for one read for a check.
    pub fn shown(&self) -> &str {
        &self.shown
    }

    /// Whether this is an address, which a search looks for within a scope it states.
    pub fn is_address(&self) -> bool {
        matches!(self.target, ReferenceTarget::Address { .. })
    }

    /// States what a search for this address covers within `limits`; nothing for a fingerprint.
    pub fn show_search(&self, limits: SearchLimits) {
        if let ReferenceTarget::Address { address, path } = &self.target {
            show_search(address, path.as_ref(), limits);
        }
    }

    /// The library's reference with `passphrase` in place of the one read.
    pub fn reference_with<'a>(&'a self, passphrase: &'a str) -> Reference<'a> {
        self.target.with(passphrase)
    }

    /// Reads the reference with a coin and a path from the command line. A script without a coin
    /// means Bitcoin, and says so. A receiving address shows what the search covers. Without
    /// `wallet_has_passphrase` the passphrase is asked as `mhfe check` asks it, Enter for none;
    /// with it, only of a wallet that has one.
    fn read_given(
        input: &mut Input,
        fingerprint: bool,
        coin: Option<Coin>,
        path: Option<DerivationPath>,
        operation: Operation,
        wallet_has_passphrase: Option<bool>,
    ) -> Result<Self, Failure> {
        let target = if fingerprint {
            ReferenceTarget::Fingerprint(read_public(
                input,
                "Master key fingerprint, eight hex digits: ",
                Some(("Master key", "fingerprint ")),
                parse_fingerprint,
            )?)
        } else {
            let (coin, assumed) = match coin {
                Some(coin) => {
                    if !input.is_script() {
                        // The summary names the coin, as the question would have recorded it.
                        choice::record("Coin", coin.name());
                    }
                    (coin, false)
                }
                None if input.is_script() => {
                    choice::record(
                        "Coin",
                        &format!("{}, as no --coin was given", SCRIPT_DEFAULT_COIN.name()),
                    );
                    (SCRIPT_DEFAULT_COIN, true)
                }
                None => (ask_for_coin(input)?, false),
            };
            let address = read_public(
                input,
                &format!("Receiving address ({}): ", coin.address_forms()),
                Some(("Address", "")),
                |text| match Address::parse(coin, text) {
                    // The coin assumed comes first, where the refusal starts.
                    Err(MhfeError::InvalidAddress(reason)) if assumed => {
                        Err(MhfeError::InvalidAddress(format!(
                            "without --coin a script compares with a {} address, and {reason}; \
                             name the address's coin with --coin, such as --coin ethereum",
                            coin.name()
                        )))
                    }
                    parsed => parsed,
                },
            )?;
            show_search(&address, path.as_ref(), SearchLimits::default());
            ReferenceTarget::Address { address, path }
        };
        let passphrase = match wallet_has_passphrase {
            // A separate secret from the MHFE password; most wallets have none.
            None => read_passphrase_of(input, operation, "the wallet")?,
            Some(true) => read_passphrase_named(input, operation, "the wallet")?,
            Some(false) => LockedText::copy_of(""),
        };
        Ok(Self {
            target,
            passphrase,
            shown: String::new(),
        })
    }

    pub fn reference(&self) -> Reference<'_> {
        self.reference_with(&self.passphrase)
    }
}

/// The answers that compare with the wallet itself.
pub fn wallet_answers() -> [Answer; 2] {
    [
        Answer::new(
            "A receiving address (recommended)",
            "checks the wallet and its passphrase",
        ),
        Answer::new(
            "The master key fingerprint",
            "eight hex digits; quick, weaker",
        ),
    ]
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
const NO_LENGTH_FOUND: &[&str] = &[
    "No length of 12 to 21 words passes its built-in check.",
    "A 24-word phrase is compared with an address or the fingerprint.",
];

/// After detection found no length, the person states it, and the same recovery is compared
/// again: a 12- to 21-word length with its built-in check, which detection tried already, and a
/// 24-word phrase with a receiving address or the fingerprint of the wallet.
fn ask_length_after_detection(
    input: &mut Input,
    recovered: &RecoveredForCheck,
    coin: Option<Coin>,
    path: Option<DerivationPath>,
) -> Result<Compared, Failure> {
    let words = phrase_length::ask_stated(input, &WORD_COUNTS, NO_LENGTH_FOUND, "Original")?;
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

/// Reads a public answer, such as an address, as one step, again until `parse` accepts it; the
/// summary then records it as `record`, if given: a label, and words to put before the answer.
/// A caller whose `parse` accepts more than the answer it asks for records it itself, once read.
fn read_public<T>(
    input: &mut Input,
    prompt: &str,
    record: Option<(&str, &str)>,
    parse: impl Fn(&str) -> Result<T, MhfeError>,
) -> Result<T, Failure> {
    let mut step = Step::start(input);
    loop {
        let text = step.visible(input, prompt)?;
        match parse(&text) {
            Ok(value) => {
                step.finish()?;
                if let Some((label, before)) = record {
                    choice::record(label, &format!("{before}{}", text.trim()));
                }
                return Ok(value);
            }
            Err(error) if input.can_ask_again() => {
                step.retry(refused(&error, terminal::TYPE_AGAIN))
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// The BIP39 passphrase for the phrase + passphrase check, which the library offers only with one
/// (`wallet_check::require_passphrase`, the rule the browser package follows too): an empty one
/// is refused and asked again.
pub fn read_check_passphrase(
    input: &mut Input,
    operation: Operation,
) -> Result<LockedText, Failure> {
    let passphrase = read_passphrase_until(input, operation, "the wallet", |passphrase| {
        wallet_check::require_passphrase(passphrase)
            .map_err(|_| "Type the passphrase: the phrase + passphrase check needs one.".to_owned())
    })?;
    choice::record("Passphrase", "typed");
    Ok(passphrase)
}

/// The private screen of `operation` on which the BIP39 passphrase of `whose` is typed, with the
/// reminder that it is not the container password.
pub fn passphrase_screen(input: &Input, operation: Operation, whose: &str) -> PrivateScreen {
    let screen = PrivateScreen::enter(input, operation.title());
    if screen.is_active() {
        eprintln!();
        style::hint(&format!(
            "Part of {whose}, as a 25th word; it is NOT the container password."
        ));
    }
    screen
}

/// Reads a BIP39 passphrase on the private screen of `operation`, again until `accept` takes it;
/// `accept` gives the message for one it refuses.
fn read_passphrase_until(
    input: &mut Input,
    operation: Operation,
    whose: &str,
    accept: impl Fn(&str) -> Result<(), String>,
) -> Result<LockedText, Failure> {
    let _screen = passphrase_screen(input, operation, whose);
    loop {
        let passphrase = input.secret(&format!("BIP39 passphrase of {whose}"))?;
        let message = match accept(&passphrase) {
            Ok(()) => return Ok(passphrase),
            Err(message) => message,
        };
        if !input.can_ask_again() {
            return Err(Failure::invalid_input(message));
        }
        style::retry(message);
    }
}

/// The BIP39 passphrase used with `whose`, such as "the container phrase", which the person has
/// said there is: it may not be empty.
pub fn read_passphrase_named(
    input: &mut Input,
    operation: Operation,
    whose: &str,
) -> Result<LockedText, Failure> {
    read_passphrase_until(input, operation, whose, |passphrase| {
        (!passphrase.is_empty())
            .then_some(())
            .ok_or_else(|| format!("Type the passphrase: you said {whose} has one."))
    })
}

/// `--passphrase-used yes|no`: the answer to whether a BIP39 passphrase is used, as an option of
/// the commands that ask it (the owner's rule that every answer that is not a secret is an option
/// too). The passphrase itself is never an option: it is typed, or a script's line.
#[derive(Args)]
pub struct PassphraseUsedOption {
    /// Whether a BIP39 passphrase is used: yes or no
    #[arg(long = "passphrase-used", value_name = "yes|no", value_parser = parse_yes_no)]
    used: Option<bool>,
}

impl PassphraseUsedOption {
    /// The answer given, or `None` to ask at a terminal.
    pub fn given(&self) -> Option<bool> {
        self.used
    }
}

fn parse_yes_no(text: &str) -> Result<bool, String> {
    match text {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err("give yes or no".to_owned()),
    }
}

/// Whose BIP39 passphrase a question is about, named in it and in its field.
pub const CONTAINER_PHRASE: &str = "the container phrase";
pub const ORIGINAL_SEED_PHRASE: &str = "the original seed phrase";

/// Asks whether a BIP39 passphrase is used with `whose` and, if so, reads it; empty for none.
pub fn ask_passphrase(
    input: &mut Input,
    operation: Operation,
    whose: &str,
) -> Result<LockedText, Failure> {
    ask_passphrase_explained(input, operation, whose, &[], None, None)
}

/// Why a recovery asks for the passphrase of a 24-word reading: the 16-bit source check, which
/// every recovery evaluates (the specification's recovery rules). Longer than the usual link, as
/// the owner asked (2026-10-09): nothing else on the screen says why a tool that only decrypts
/// wants a passphrase.
pub const SOURCE_CHECK_WHY: &[&str] = &[
    "A new 24-word phrase can carry a 16-bit check tied to its BIP39",
    "passphrase, as mhfe new offers. The container does not show whether",
    "this one does, so MHFE tests every 24-word reading with the passphrase",
    "you give here, or with none.",
    "",
    "A pass makes a right password very likely. A failure means something",
    "only if the wallet was made with the check. The passphrase is used for",
    "this test alone and is not kept.",
];

/// [`ask_passphrase`] with an explanation under the question and a link to `more`.
pub fn ask_passphrase_explained(
    input: &mut Input,
    operation: Operation,
    whose: &str,
    explanation: &[&str],
    more: Option<&str>,
    given: Option<bool>,
) -> Result<LockedText, Failure> {
    match given {
        Some(false) => return Ok(LockedText::copy_of("")),
        Some(true) => return read_passphrase_named(input, operation, whose),
        None => {}
    }
    let text = format!("Is a BIP39 passphrase used with {whose}?");
    let answers = passphrase_answers(whose);
    let question = Question {
        text: &text,
        explanation,
        more,
        record: None,
    };
    // A step of its own, headed by what comes before it, before any work starts.
    if input.choose(&question, &answers)? == 0 {
        return Ok(LockedText::copy_of(""));
    }
    read_passphrase_named(input, operation, whose)
}

fn passphrase_answers(whose: &str) -> [Answer; 2] {
    [
        Answer::new("No", format!("{whose} alone")),
        Answer::new("Yes", "type it next"),
    ]
}

/// The BIP39 passphrase of the original seed phrase for its own checks: a person is asked
/// whether one is used, and a script gives a line, empty for none.
fn read_own_checks_passphrase(
    input: &mut Input,
    operation: Operation,
) -> Result<LockedText, Failure> {
    if input.is_script() {
        return read_passphrase_of(input, operation, ORIGINAL_SEED_PHRASE);
    }
    ask_passphrase(input, operation, ORIGINAL_SEED_PHRASE)
}

/// The BIP39 passphrase of a wallet named `wallet`, such as "the main wallet", or none.
pub fn read_passphrase_of(
    input: &mut Input,
    operation: Operation,
    wallet: &str,
) -> Result<LockedText, Failure> {
    let screen = passphrase_screen(input, operation, wallet);
    let passphrase = input.secret(&format!(
        "BIP39 passphrase of {wallet}, or Enter if it has none"
    ))?;
    drop(screen);
    let what = if passphrase.is_empty() {
        "none"
    } else {
        "typed"
    };
    choice::record("Passphrase", what);
    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_coin_explanation_fits_a_list() {
        assert!(crate::choice::fits(COIN_EXPLANATION));
        assert!(crate::choice::fits(SOURCE_CHECK_WHY));
    }

    #[test]
    fn only_a_wallet_reference_claims_the_wallet() {
        let evidence = |built_in_check, wallet_check| CheckEvidence {
            outcome: mhfe::CheckOutcome::Matches { path: None },
            built_in_check,
            wallet_check,
        };
        let built_in = matched_lines(
            Choice::BuiltInCheck(12),
            &evidence(Some(12), None),
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
            assert!(matched_lines(choice, &evidence(None, None), true, None)[1].contains("wallet"));
        }
    }

    /// Every check that passed is a line of its own, a check the same recovery shows besides
    /// included; a phrase + passphrase check that fails is not listed.
    #[test]
    fn every_passed_check_is_listed() {
        let evidence = CheckEvidence {
            outcome: mhfe::CheckOutcome::Matches { path: None },
            built_in_check: Some(15),
            wallet_check: Some(true),
        };
        let found_by = "the container's own wallet: master key fingerprint e0f73b78";
        assert_eq!(
            matched_lines(Choice::Fingerprint, &evidence, true, Some(found_by)),
            [
                "the container phrase passes its BIP39 checksum",
                found_by,
                "the master key fingerprint of the wallet, with this BIP39 passphrase",
                "the built-in check of a 15-word original seed phrase",
                "the phrase + passphrase check: its first 16 bits are zero",
            ]
        );
        let failing = CheckEvidence {
            wallet_check: Some(false),
            built_in_check: None,
            ..evidence
        };
        assert_eq!(
            matched_lines(Choice::Address, &failing, false, None).len(),
            2
        );
    }
}
