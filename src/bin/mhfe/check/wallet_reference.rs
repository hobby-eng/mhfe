//! The wallet references a person types: a receiving address of a coin, or the master key
//! fingerprint, with the wallet's BIP39 passphrase.

use mhfe::memory::LockedText;
use mhfe::wallet::{
    fingerprint_text, parse_fingerprint, Address, AddressSearch, Coin, DerivationPath, SearchLimits,
};
use mhfe::{MhfeError, Reference, ReferenceTarget};
use zeroize::Zeroizing;

use super::passphrase::{read_passphrase_named, read_passphrase_of};
use crate::choice::{self, Answer, Question};
use crate::exit::{refused, Failure};
use crate::settings::Operation;
use crate::style;
use crate::terminal::{self, Input, Step};

/// The coin of the address of a script that names none, as in v0.4.0 and v0.5.0, so that such a
/// script keeps working. It is never assumed silently: the summary names it, and the refusal of
/// an address of another coin says how to name that coin (AUD-010). A person is always asked, and
/// a page of the browser package must name the coin.
const SCRIPT_DEFAULT_COIN: Coin = Coin::Bitcoin;

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
    pub(super) fn read_given(
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

/// States what a search for `address` covers, before the work starts.
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
            mhfe::grouped(search.addresses())
        )
    };
    style::fact_before_work("Search", text);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_coin_explanation_fits_a_list() {
        assert!(crate::choice::fits(COIN_EXPLANATION));
    }
}
