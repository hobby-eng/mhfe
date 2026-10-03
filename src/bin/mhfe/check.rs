//! `mhfe check`: rehearses a recovery and reports only "matches" or "does not match".
//!
//! Nothing of the recovered phrase is shown, and a wrong password gives no hint of how close
//! it was. The strong reference is a receiving address of the wallet; the master key fingerprint
//! is a quick, weaker check; the built-in check of a short original confirms only that the
//! password recovers a consistent phrase.

use anstream::{eprintln, println};
use clap::Args;
use mhfe::wallet::{parse_fingerprint, BitcoinAddress, DerivationPath, SearchLimits};
use mhfe::{MhfeError, Reference, Suite, WordCount};
use zeroize::Zeroizing;

use crate::choice::{self, Answer, Question};
use crate::exit::{capitalize, Failure, NO_MATCH, SUCCESS};
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
        "Asks for a Bitcoin address of the wallet, mainnet or testnet: legacy (1..., BIP44), \
         nested SegWit (3..., BIP49), native SegWit (bc1q..., BIP84) or Taproot (bc1p..., \
         BIP86). It searches the first 100 receiving and change addresses of accounts 0 to 9 \
         on the standard path of that address type.",
        "A match confirms the phrase, the wallet and its BIP39 passphrase together.",
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
    let address: BitcoinAddress;
    let passphrase: Zeroizing<String>;
    let limits = SearchLimits::default();
    let reference = match choice {
        Choice::Address => {
            address = read_public(
                &mut input,
                "Receiving address of the wallet: ",
                ("Address", ""),
                str::parse,
            )?;
            show_search(&address, options.path.as_ref(), limits);
            passphrase = read_passphrase(&mut input)?;
            Reference::Address {
                address: &address,
                passphrase: &passphrase,
                path: options.path.as_ref(),
                limits,
            }
        }
        Choice::Fingerprint => {
            let fingerprint = read_public(
                &mut input,
                "Master key fingerprint, eight hex digits: ",
                ("Master key", "fingerprint "),
                parse_fingerprint,
            )?;
            passphrase = read_passphrase(&mut input)?;
            Reference::Fingerprint {
                fingerprint,
                passphrase: &passphrase,
            }
        }
        Choice::BuiltInCheck(words) => Reference::BuiltInCheck {
            words: WordCount::new(words)?,
        },
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
                "The password, PIM, memory level, container or word count may be wrong. The check \
                 cannot tell which."
            }
            _ => {
                "The password, PIM, memory level, container, BIP39 passphrase or reference may be \
                 wrong. The check cannot tell which."
            }
        });
        Ok(NO_MATCH)
    }
}

/// States before the check what an address is and which addresses are searched for it, as the
/// specification asks of a search: a "does not match" covers only these.
fn show_search(address: &BitcoinAddress, path: Option<&DerivationPath>, limits: SearchLimits) {
    let kind = address.address_type();
    style::fact(
        "Type",
        format!(
            "{}, {} (BIP{})",
            address.network().name(),
            kind.name(),
            kind.purpose()
        ),
    );
    let search = match path {
        Some(path) => format!("only {path}"),
        None => {
            let last = |count: u32| count - 1;
            format!(
                "m/{}'/{}'/0'-{}'/0-1/0-{}, {} addresses",
                kind.purpose(),
                address.network().coin_type(),
                last(limits.accounts()),
                last(limits.indexes()),
                grouped(2 * u64::from(limits.accounts()) * u64::from(limits.indexes()))
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
            Some(
                "A fingerprint is a quick 32-bit check; a receiving address (--address) confirms \
                 the wallet more strongly.",
            ),
        ),
        Choice::BuiltInCheck(words) => (
            format!("the password and settings recover a consistent {words}-word phrase."),
            Some(
                "This built-in check does not show that it is your wallet and does not check a \
                 BIP39 passphrase. Compare a receiving address (--address) for that.",
            ),
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
    }
    let question = Question::new(
        "What should the recovered seed phrase be compared with?",
        "Compare",
    );
    match input.choose(&question, &answers)? {
        0 => Ok(Choice::Address),
        1 => Ok(Choice::Fingerprint),
        _ => ask_for_original_length(input).map(Choice::BuiltInCheck),
    }
}

/// The length of the original, for its built-in check.
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
fn read_passphrase(input: &mut Input) -> Result<Zeroizing<String>, Failure> {
    let screen = PrivateScreen::enter(input, Operation::Check.title());
    if screen.is_active() {
        eprintln!();
    }
    let passphrase = input.secret("BIP39 passphrase of the wallet, or Enter if it has none")?;
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
    fn counts_are_grouped_by_thousands() {
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(2_000), "2,000");
        assert_eq!(grouped(1_234_567), "1,234,567");
    }

    #[test]
    fn only_a_wallet_reference_claims_the_wallet() {
        let (built_in, limit) = match_meaning(Choice::BuiltInCheck(12));
        assert!(!built_in.contains("wallet"), "{built_in}");
        assert!(limit
            .unwrap()
            .contains("does not show that it is your wallet"));
        for choice in [Choice::Address, Choice::Fingerprint] {
            assert!(match_meaning(choice).0.contains("recovered wallet"));
        }
    }
}
