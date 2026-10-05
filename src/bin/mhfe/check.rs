//! `mhfe check`: rehearses a recovery and reports only "matches" or "does not match".
//!
//! Nothing of the recovered phrase is shown, and a wrong password gives no hint of how close
//! it was. The strong reference is a receiving address of the wallet; the master key fingerprint
//! is a quick, weaker check; the built-in check of a short original confirms only that the
//! password recovers a consistent phrase.

use anstream::{eprintln, println};
use clap::Args;
use mhfe::wallet::{parse_fingerprint, Address, Coin, DerivationPath, SearchLimits};
use mhfe::{MhfeError, Reference, Suite, WordCount};

use crate::choice::{self, Answer, Question};
use crate::exit::{capitalize, Failure, NO_MATCH, SUCCESS};
use crate::locked_text::LockedText;
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT};
use crate::terminal::{self, Input, PrivateScreen, Progress, Step};

#[derive(Args)]
#[command(group = clap::ArgGroup::new("reference").args(["address", "fingerprint", "words"]))]
pub struct Options {
    #[command(flatten)]
    settings: Settings,

    /// Compare with a receiving address (strong check)
    #[arg(long, long_help = address_help())]
    address: bool,

    /// With --address: the coin of the address (default bitcoin)
    #[arg(long, value_name = "COIN", requires = "address", long_help = coin_help())]
    coin: Option<Coin>,

    /// Compare with the master key fingerprint (quick, weaker)
    #[arg(long, long_help = fingerprint_help())]
    fingerprint: bool,

    /// Only the built-in check of a 12- to 21-word original
    #[arg(long, value_name = "N", long_help = words_help())]
    words: Option<usize>,

    /// With --address: look only at this derivation path
    #[arg(long, value_name = "PATH", requires = "address", long_help = path_help())]
    path: Option<DerivationPath>,

    /// Read the answers from standard input (for scripts)
    #[arg(long, requires = "reference", long_help = stdin_help())]
    stdin: bool,
}

fn address_help() -> String {
    style::option_help(&[
        "Compare with a receiving address (strong check).",
        "Asks for the coin and a single-key receiving address of the wallet: Bitcoin (1..., \
         3..., bc1q... or bc1p..., also on testnet), Ethereum and EVM networks (0x...), XRP, \
         Tron, Zcash (transparent t1...), Dogecoin, Bitcoin Cash, Litecoin, Ethereum Classic, \
         Cosmos, Injective or Dash. It searches the first 100 receiving and change addresses \
         of accounts 0 to 9 on the standard paths of that address, which it shows before the \
         check.",
        "A match confirms the phrase, the wallet and its BIP39 passphrase together.",
    ])
}

fn coin_help() -> String {
    let coins: Vec<&str> = Coin::ALL.iter().map(|coin| coin.id()).collect();
    style::option_help(&[
        "With --address: the coin of the address (default bitcoin).",
        &format!(
            "One of {}. ethereum covers every EVM network, such as BNB Smart Chain, Polygon, \
             Avalanche C-Chain, Arbitrum, Optimism and Base. Without this option a person is \
             asked, and a script means bitcoin.",
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
        "Only the built-in check of a 12- to 21-word original.",
        "N is the length of the original: 12, 15, 18 or 21. Nothing more is asked for. A match \
         confirms the password and the settings only, not the wallet or a BIP39 passphrase. A \
         24-word original and a container as long as its original have no built-in check; \
         compare them with an address or the fingerprint.",
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
         reference and the BIP39 passphrase (an empty line if none), one per line. Output: \
         \"matches\" with exit code 0, or \"does not match\" with exit code 3.",
    ])
}

/// The top of `mhfe check --help`.
pub fn about() -> String {
    style::command_about(&[
        "Rehearse a recovery without ever showing the phrase",
        "Runs the same 12 rounds as a recovery and compares the result with something you know \
         about the wallet: a receiving address, the master key fingerprint, or, for a 12- to \
         21-word original, its built-in check. Without a reference option it offers a list.",
    ])
}

/// Lengths of an original that carries a built-in check; a 24-word original fills the state.
const BUILT_IN_CHECK_LENGTHS: [usize; 4] = [12, 15, 18, 21];

/// The reference as typed, before it is read into its type.
#[derive(Clone, Copy)]
enum Choice {
    Address,
    Fingerprint,
    BuiltInCheck(usize),
    /// The wallet check of a phrase that `mhfe new` made with one (a draft).
    WalletCheck,
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
                "Built-in check of a 12-word original",
            ),
            (
                "mhfe check --address --path \"m/84'/0'/0'/0/5\"",
                "Compare with the address at this one path",
            ),
            (
                "mhfe check --fingerprint --pim 1 --mem 1",
                "The fingerprint, with the settings used for encryption",
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
            ("Password", "hidden"),
            (
                "Reference",
                "a receiving address, the fingerprint, or the word count",
            ),
            (
                "BIP39 passphrase",
                "hidden; press Enter if the wallet has none",
            ),
        ],
    );
    let note = style::help_note(
        "The check shows only whether the recovery matches, never any part of the phrase.",
    );
    format!("{asks}\n{}\n{note}", examples())
}

pub fn run(options: Options) -> Result<i32, Failure> {
    // Refused before anything is asked: only a short original carries a built-in check.
    if let Some(words) = options.words {
        if !BUILT_IN_CHECK_LENGTHS.contains(&words) {
            return Err(Failure::invalid_input(
                "--words must be 12, 15, 18 or 21: a 24-word original has no built-in check; \
                 compare it with --address or --fingerprint.",
            ));
        }
    }
    let mut input = Input::new(options.stdin);
    let work = settings::choose(options.settings, &mut input, Operation::Check)?;

    let (container, suite) = terminal::read_container(&mut input, Operation::Check.title())?;
    let same_length = suite == Suite::SameLength;
    if same_length && options.words.is_some() {
        // Refused before the password is asked: there is nothing to check without a reference.
        return Err(MhfeError::NoBuiltInCheck {
            container_words: container.split(' ').count(),
        }
        .into());
    }
    let password = terminal::read_password(&mut input, Operation::Check.title())?;
    let choice = match (options.address, options.fingerprint, options.words) {
        (true, _, _) => Choice::Address,
        (_, true, _) => Choice::Fingerprint,
        (_, _, Some(words)) => Choice::BuiltInCheck(words),
        _ => ask_for_choice(&mut input, same_length)?,
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
            )?;
            wallet_reference.reference()
        }
        Choice::BuiltInCheck(words) => Reference::BuiltInCheck {
            words: WordCount::new(words)?,
        },
        Choice::WalletCheck => {
            check_passphrase = read_passphrase(&mut input, Operation::Check)?;
            // Refused before the long computation: the check is tested with its passphrase only.
            if check_passphrase.is_empty() {
                return Err(MhfeError::WalletCheckNeedsPassphrase.into());
            }
            Reference::WalletCheck {
                passphrase: &check_passphrase,
            }
        }
    };

    let mut mhfe = settings::reserve_memory(work)?;
    let mut progress = Progress::start();
    let outcome = mhfe.check(&container, &password, &reference, &mut |round, rounds| {
        progress.round_starts(round, rounds);
        Ok(())
    })?;
    progress.finish();
    let matches = outcome.matches();

    eprintln!();
    if input.is_script() {
        // Scripts read exactly these words.
        println!("{}", if matches { "matches" } else { "does not match" });
    } else if matches {
        let (meaning, limit) = match_meaning(choice);
        println!("{} {meaning}", paint(style::GOOD, "✓ matches:"));
        // Which account and address of the wallet it is; a path given with --path is shown too.
        if let Some(path) = outcome.path() {
            style::fact("Found at", paint(ACCENT, path));
        }
        if let Some(limit) = limit {
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
                "The password, a setting, the container or the word count is wrong."
            }
            Choice::WalletCheck => {
                "If this wallet was made with a check, the password, a setting or the passphrase is \
                 wrong."
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

/// States before the check what an address is and which addresses are searched for it, as the
/// specification asks of a search: a "does not match" covers only these.
/// The roots of a search as one pattern, every step hardened: "44'/5'", or "44'/{145,0}'" where a
/// coin has two coin types. Roots differ only in that step.
fn root_pattern(roots: &[Vec<u32>]) -> String {
    let steps = roots.first().map_or(0, Vec::len);
    (0..steps)
        .map(|step| {
            let mut values: Vec<String> = Vec::new();
            for root in roots {
                let value = root[step].to_string();
                if !values.contains(&value) {
                    values.push(value);
                }
            }
            match values.as_slice() {
                [only] => format!("{only}'"),
                several => format!("{{{}}}'", several.join(",")),
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn show_search(address: &Address, path: Option<&DerivationPath>, limits: SearchLimits) {
    if let Some(kind) = address.type_description() {
        style::fact("Type", kind);
    }
    let search = match path {
        Some(path) => format!("only {path}"),
        None => {
            let roots = address.search_roots();
            let chains = if address.hardened_chains() {
                "0'-1'"
            } else {
                "0-1"
            };
            let addresses =
                roots.len() as u64 * 2 * u64::from(limits.accounts()) * u64::from(limits.indexes());
            format!(
                "m/{}/0'-{}'/{chains}/0-{}, {} addresses",
                root_pattern(&roots),
                limits.accounts() - 1,
                limits.indexes() - 1,
                grouped(addresses)
            )
        }
    };
    style::fact("Search", search);
}

/// A count with thousands separated by commas, such as "2,000".
fn grouped(count: u64) -> String {
    let digits = count.to_string();
    let mut text = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            text.push(',');
        }
        text.push(digit);
    }
    text
}

/// What a match shows, and its limit. Only an address or a fingerprint identifies the wallet;
/// the built-in check of a short original says nothing about the wallet or a BIP39 passphrase.
fn match_meaning(choice: Choice) -> (String, Option<&'static str>) {
    match choice {
        Choice::Address => (
            "the recovered wallet, with this BIP39 passphrase, has this receiving address."
                .to_owned(),
            None,
        ),
        Choice::Fingerprint => (
            "the recovered wallet, with this BIP39 passphrase, has this master key fingerprint."
                .to_owned(),
            Some("A fingerprint is a quick 32-bit check; an address (--address) is stronger."),
        ),
        Choice::BuiltInCheck(words) => (
            format!("the password and settings recover a consistent {words}-word phrase."),
            Some("It does not prove the wallet or its passphrase; an address (--address) does."),
        ),
        Choice::WalletCheck => (
            "the recovered phrase with this passphrase passes its wallet check (16 bits)."
                .to_owned(),
            Some("It does not prove the wallet; an address (--address) does."),
        ),
    }
}

/// Asks what to compare with. A same-length container has no built-in check, so it is offered
/// only the address and the fingerprint.
fn ask_for_choice(input: &mut Input, same_length: bool) -> Result<Choice, Failure> {
    let mut answers = vec![
        Answer::new(
            "A receiving address (recommended)",
            "checks the wallet and its passphrase",
        ),
        Answer::new(
            "The master key fingerprint",
            "eight hex digits; quick, weaker",
        ),
    ];
    if !same_length {
        answers.push(Answer::new(
            "Only the built-in check",
            "checks the password, not the wallet",
        ));
        answers.push(Answer::new(
            "Its wallet check",
            "made by mhfe new; needs the passphrase",
        ));
    }
    let question = Question::new(
        "What should the recovered seed phrase be compared with?",
        "Compare",
    );
    match input.choose(&question, &answers)? {
        0 => Ok(Choice::Address),
        1 => Ok(Choice::Fingerprint),
        2 => ask_for_original_length(input).map(Choice::BuiltInCheck),
        _ => Ok(Choice::WalletCheck),
    }
}

/// The length of the original, for its built-in check.
/// A reference of the wallet that the owner typed, a receiving address or the master key
/// fingerprint, with the wallet's BIP39 passphrase: what a check compares a recovery with, and what
/// confirms a recovery without a built-in check before it is encrypted again.
pub struct WalletReference {
    kind: ReferenceKind,
    path: Option<DerivationPath>,
    passphrase: LockedText,
}

enum ReferenceKind {
    Address(Address),
    Fingerprint([u8; 4]),
}

impl WalletReference {
    /// Reads a receiving address, of a coin asked for, or with `fingerprint` the master key
    /// fingerprint, and then the passphrase on the private screen of `operation`.
    pub fn read(
        input: &mut Input,
        fingerprint: bool,
        operation: Operation,
    ) -> Result<Self, Failure> {
        Self::read_given(input, fingerprint, None, None, operation)
    }

    /// [`WalletReference::read`] with a coin and a path from the command line. A script without
    /// a coin means Bitcoin. A receiving address shows what the search covers.
    fn read_given(
        input: &mut Input,
        fingerprint: bool,
        coin: Option<Coin>,
        path: Option<DerivationPath>,
        operation: Operation,
    ) -> Result<Self, Failure> {
        let kind = if fingerprint {
            ReferenceKind::Fingerprint(read_public(
                input,
                "Master key fingerprint, eight hex digits: ",
                ("Master key", "fingerprint "),
                parse_fingerprint,
            )?)
        } else {
            let coin = match coin {
                Some(coin) => {
                    if !input.is_script() {
                        // The summary names the coin, as the question would have recorded it.
                        choice::record("Coin", coin.name());
                    }
                    coin
                }
                None if input.is_script() => Coin::Bitcoin,
                None => ask_for_coin(input)?,
            };
            let address = read_public(
                input,
                &format!("Receiving address ({}): ", coin.address_forms()),
                ("Address", ""),
                |text| Address::parse(coin, text),
            )?;
            show_search(&address, path.as_ref(), SearchLimits::default());
            ReferenceKind::Address(address)
        };
        let passphrase = read_passphrase(input, operation)?;
        Ok(Self {
            kind,
            path,
            passphrase,
        })
    }

    pub fn reference(&self) -> Reference<'_> {
        match &self.kind {
            ReferenceKind::Address(address) => Reference::Address {
                address,
                passphrase: &self.passphrase,
                path: self.path.as_ref(),
                limits: SearchLimits::default(),
            },
            ReferenceKind::Fingerprint(fingerprint) => Reference::Fingerprint {
                fingerprint: *fingerprint,
                passphrase: &self.passphrase,
            },
        }
    }
}

fn ask_for_original_length(input: &mut Input) -> Result<usize, Failure> {
    let answers = BUILT_IN_CHECK_LENGTHS.map(|words| Answer::new(format!("{words} words"), ""));
    let question = Question::new("How many words does the original have?", "Original");
    let chosen = input.choose(&question, &answers)?;
    Ok(BUILT_IN_CHECK_LENGTHS[chosen])
}

/// Reads a public answer, such as an address, as one step, again until `parse` accepts it; the
/// summary then records it as `record`: a label, and words to put before the answer.
fn read_public<T>(
    input: &mut Input,
    prompt: &str,
    record: (&str, &str),
    parse: impl Fn(&str) -> Result<T, MhfeError>,
) -> Result<T, Failure> {
    let mut step = Step::start(input);
    loop {
        let text = step.visible(input, prompt)?;
        match parse(&text) {
            Ok(value) => {
                step.finish()?;
                let (label, before) = record;
                choice::record(label, &format!("{before}{}", text.trim()));
                return Ok(value);
            }
            Err(error) if input.can_ask_again() => step.retry(format!(
                "{}. Please type it again.",
                capitalize(&error.to_string())
            )),
            Err(error) => return Err(error.into()),
        }
    }
}

/// The BIP39 passphrase is a separate secret from the MHFE password; most wallets have none. It is
/// typed on the private screen, and the summary records only whether there is one.
pub fn read_passphrase(input: &mut Input, operation: Operation) -> Result<LockedText, Failure> {
    read_passphrase_of(input, operation, "the wallet")
}

/// [`read_passphrase`] of a wallet named otherwise, such as "the main wallet".
pub fn read_passphrase_of(
    input: &mut Input,
    operation: Operation,
    wallet: &str,
) -> Result<LockedText, Failure> {
    let screen = PrivateScreen::enter(input, operation.title());
    if screen.is_active() {
        eprintln!();
    }
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
    }

    #[test]
    fn search_roots_read_as_one_pattern() {
        assert_eq!(root_pattern(&[vec![44, 5]]), "44'/5'");
        assert_eq!(root_pattern(&[vec![44, 145], vec![44, 0]]), "44'/{145,0}'");
        assert_eq!(root_pattern(&[vec![9, 5, 17]]), "9'/5'/17'");
    }

    #[test]
    fn counts_are_grouped_by_thousands() {
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(2_000), "2,000");
        assert_eq!(grouped(1_234_567), "1,234,567");
    }

    #[test]
    fn only_a_wallet_reference_claims_the_wallet() {
        let (built_in, limit) = match_meaning(Choice::BuiltInCheck(12));
        assert!(!built_in.contains("wallet"), "{built_in}");
        assert!(limit.unwrap().contains("does not prove the wallet"));
        for choice in [Choice::Address, Choice::Fingerprint] {
            assert!(match_meaning(choice).0.contains("recovered wallet"));
        }
    }
}
