//! `mhfe rekey`: the same seed phrase in a new container, under a new password or new settings.
//! The old container is recovered and the phrase is confirmed before it is encrypted again (the
//! re-encryption guard, `Mhfe::recover_confirmed`): by its built-in check at the length the owner
//! states, by an address or the fingerprint of the wallet, or, if the owner chooses it, by the
//! owner comparing the phrase, shown on a private screen, with their backup. Encrypting under the
//! old password and comparing would prove nothing.

use clap::{Args, ValueEnum};
use mhfe::memory::LockedText;
use mhfe::operation::{Keep, Sealed, Stage};
use mhfe::rekey::{ConfirmedPhrase, Rekey, ReplacementRehearsal};
use mhfe::wallet::fingerprint_text;
use mhfe::wallet_check::WALLET_CHECK_BITS;
use mhfe::{
    Confirmation, ConfirmationNeeded, ContainerFacts, MhfeError, OriginalFacts, Password,
    PhraseLength, RecoveredForRekey, WordCount, WorkFactor,
};

use crate::check::{self, WalletReference};
use crate::choice::{self, Answer, Question};
use crate::container_repair::{RepairOption, RepairWordsOption};
use crate::encrypt;
use crate::exit::{Failure, SUCCESS};
use crate::flow::Flow;
use crate::made_password::{NewPasswordOption, PasswordKind};
use crate::phrase_length;
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT, HEADING};
use crate::terminal::{self, Input, Progress, Wallet};

#[derive(Args)]
pub(crate) struct Options {
    /// The settings of the old container
    #[command(flatten)]
    old: Settings,

    #[command(flatten)]
    repair: RepairOption,

    #[command(flatten)]
    repair_words: RepairWordsOption,

    #[arg(long = "new-pim", value_name = "N",
          help = format!("PIM of the new container, {} (default 0)", settings::pim_range()))]
    new_pim: Option<u32>,

    #[arg(long = "new-mem", value_name = "LEVEL", long_help = new_memory_help(),
          help = format!("New memory level, {} (default 0: {})", settings::level_range(), settings::memory_text(0)))]
    new_memory_level: Option<u32>,

    #[arg(long, value_name = "N", value_parser = phrase_length::parse, long_help = words_help(),
          help = format!("Words of the seed phrase: {}, or {}", phrase_length::length_range(), phrase_length::AUTO))]
    words: Option<PhraseLength>,

    /// Confirm by: check, address, fingerprint or show
    #[arg(long, value_name = "HOW", hide_possible_values = true, long_help = confirm_help())]
    confirm: Option<Kind>,

    #[command(flatten)]
    passphrase_used: check::PassphraseUsedOption,

    #[command(flatten)]
    new_password: NewPasswordOption,
}

fn new_memory_help() -> String {
    style::option_help(&[
        &format!(
            "Memory level of the new container, {} (default 0: {}).",
            settings::level_range(),
            settings::memory_text(0)
        ),
        "Without --new-pim and --new-mem the new settings are asked at a terminal.",
    ])
}

fn words_help() -> String {
    style::option_help(&[
        &format!(
            "Words of the seed phrase: {} or auto.",
            phrase_length::length_list()
        ),
        "Asked when not given, unless the container tells it: a same-length container has the \
         length of its phrase. With auto the length is detected after the recovery, and an \
         address, the fingerprint or the phrase shown confirms it, asked as for 24 words: a \
         24-word phrase can pass a shorter one's check by chance.",
        "A stated length is compared with the built-in checks. One that finds another length \
         takes precedence, and then an address, the fingerprint or the phrase shown confirms \
         the phrase before it is encrypted again.",
    ])
}

fn confirm_help() -> String {
    style::option_help(&[
        &format!("How the recovered phrase is confirmed before it is encrypted again: check, its built-in \
         check, for a {} length stated with --words; address or fingerprint, of the \
         wallet, typed next; show, only if you know neither: the phrase on a private screen, to \
         compare with your written backup or enter into your wallet, and then a fingerprint to \
         rehearse the new container with.", phrase_length::short_range_words()),
        "Asked at a terminal when not given. A way the length does not allow is refused before \
         anything is computed, and after a refusal on the recovered phrase the question is asked \
         again.",
    ])
}

/// The one-line summary of the command: `-h`, the first line of `--help`, and its menu entry.
pub(crate) const SUMMARY: &str = "Change the password or settings of a container";

/// The top of `mhfe rekey --help`.
pub(crate) fn about() -> String {
    style::command_about(&[
        SUMMARY,
        "Recovers the seed phrase from the old container, confirms it, by its built-in check, by \
         a receiving address or the master key fingerprint of the wallet, or by showing it to you \
         to compare with your backup, and encrypts it under a new password or new settings. The \
         old container keeps opening the wallet with the old password until every copy of it is \
         destroyed.",
    ])
}

/// The end of `mhfe rekey -h` and `--help`.
pub(crate) fn help() -> String {
    style::examples_with_note(
        &[
            ("mhfe rekey", "A new password, with the questions as lists"),
            (
                "mhfe rekey --new-pim 1",
                "The same phrase with twice the passes",
            ),
            (
                "mhfe rekey --pim 1 --words 24",
                "From a container made with PIM 1 for a 24-word phrase",
            ),
        ],
        "Wallets that other passwords open on the old container do not move to the new one: keep \
         the old container until their funds are moved. Rehearse the new one with mhfe check.",
    )
}

pub(crate) fn run(options: Options) -> Result<i32, Failure> {
    // Every answer is a choice at the terminal; no script reads a phrase back and forth.
    let mut input = Input::terminal_only().reading_secrets()?;
    options.new_password.check(&input)?;
    options
        .repair
        .address()
        .require_address(options.confirm == Some(Kind::Address))?;
    require_confirmation_screen(&input, options.confirm)?;
    options.repair_words.check()?;
    input.require_private_result()?;
    // At a terminal every step on a screen of its own, the summary at the end.
    let flow = Flow::start(&input, Operation::Rekey.title())?;
    let old_work = settings::choose(options.old, &mut input, Operation::Rekey)?;
    let new_settings = Settings {
        pim: options.new_pim,
        memory_level: options.new_memory_level,
    };
    new_settings.check_given(Operation::RekeyNew)?;
    if let Some(needed) = options.words.and_then(ConfirmationNeeded::of_any_container) {
        refuse_confirm(options.confirm, needed)?;
    }
    // Shown to everyone, so that it says nothing about this container (specification: a hidden
    // wallet behind an honest disclosure). Nothing is destroyed here: the old container keeps
    // opening every wallet with its passwords, so the warning heads the next screen instead of a
    // question to answer (the owner's decision of 2026-10-08, in place of AUD-007-FUN002's).
    style::warn(&keep_until_funds_moved(old_work), "");

    let (container, mut rekey) = read_old_container(&mut input, &options, old_work)?;
    let (mut how, wallet_passphrase) = choose_confirmation(&mut input, &options, &rekey)?;
    // The rounds run once; a confirmation that is refused is followed by another on the same
    // recovery (AUD-017-UI002).
    let state = recover(&rekey, old_work, &how)?;
    let recovered = confirm(
        &mut input,
        &mut rekey,
        &state,
        &mut how,
        wallet_passphrase,
        options.repair.address(),
    )?;
    drop(state);
    let recovered = record_recovery(&mut input, recovered, &how)?;
    let rehearsal = replacement_rehearsal(&mut input, &recovered)?;

    let new_work = settings::choose(new_settings, &mut input, Operation::RekeyNew)?;
    // A 24-word original too can, by rare chance, read as a shorter phrase after recovery.
    let phrase = recovered.phrase();
    let original = OriginalFacts::read(phrase.phrase())?;
    encrypt::warn_if_detection_would_mislead(
        original.other_lengths_in(container.suite()),
        phrase.words(),
    );
    drop(original);
    let repair_count = options.repair_words.choose(&mut input)?;
    let new_password =
        read_different_password(&mut input, &rekey, new_work, options.new_password.kind())?;
    let new = seal(
        &input,
        &rekey,
        &recovered,
        &new_password,
        new_work,
        repair_count,
    )?;
    flow.finish();
    print_summary(&new, new_work, &recovered, &rehearsal);
    Ok(SUCCESS)
}

/// Refuses a `--confirm` that a phrase needing `needed` cannot use, by the library's rule
/// (AUD-023-UI002): before anything is typed for a length given, and for one that depends on the
/// container once it is read.
fn refuse_confirm(confirm: Option<Kind>, needed: ConfirmationNeeded) -> Result<(), MhfeError> {
    match confirm {
        Some(Kind::BuiltInCheck) => Confirmation::BuiltInCheck.refuse_for(needed),
        _ => Ok(()),
    }
}

/// Reads the old container, the length of its phrase and its password, and makes the rekey,
/// whose own rules (length, confirmation, a new password that changes the container) are the
/// library's.
fn read_old_container(
    input: &mut Input,
    options: &Options,
    old_work: WorkFactor,
) -> Result<(ContainerFacts, Rekey), Failure> {
    let read = terminal::read_container_for(
        input,
        Operation::Rekey.title(),
        options.repair.card(Operation::Rekey, old_work),
        |container| {
            options
                .words
                .map_or(Ok(()), |length| container.require_length(length))
        },
    )?;
    let container = read.facts;
    let length = phrase_length(input, options.words, &container)?;
    refuse_confirm(options.confirm, container.confirmation_needed(length)?)?;
    // A search for missing words asked for the old password already.
    let password = match read.password {
        Some(password) => password,
        None => terminal::read_password(input, Operation::Rekey)?,
    };
    let rekey = Rekey::new(container.words(), length, password, old_work)?;
    Ok((container, rekey))
}

/// How the recovery is confirmed, with the reference typed, and whether the wallet has a BIP39
/// passphrase. A recovery without a built-in check needs another confirmation, and so does one
/// whose length is detected. It is chosen, and a reference typed, before the long computation, so
/// the user can walk away while it runs.
fn choose_confirmation(
    input: &mut Input,
    options: &Options,
    rekey: &Rekey,
) -> Result<(How, bool), Failure> {
    require_confirmation_screen(input, options.confirm)?;
    let kind = match (options.confirm, rekey.confirmation_needed()) {
        (Some(kind), _) => kind,
        (None, ConfirmationNeeded::BuiltInCheck) => Kind::BuiltInCheck,
        (None, ConfirmationNeeded::WalletOrOwner) => ask_how_to_confirm(input, true)?,
    };
    // The new container's keep list names the wallet's BIP39 passphrase, so the question is asked
    // once, before any reference: a reference without a passphrase would match the phrase's
    // wallet without one and say nothing about funds under one. Only a wallet with one is then
    // asked for it.
    let wallet_passphrase = match options.passphrase_used.given() {
        Some(used) => used,
        None => ask_wallet_passphrase(input)?,
    };
    Ok((
        how_of(input, kind, wallet_passphrase, options.repair.address())?,
        wallet_passphrase,
    ))
}

/// A show confirmation is refused before any question when its private screen cannot open.
fn require_confirmation_screen(input: &Input, kind: Option<Kind>) -> Result<(), Failure> {
    if matches!(kind, Some(Kind::Owner)) && !terminal::can_show_privately(input) {
        return Err(Failure::invalid_input(
            "--confirm show needs a terminal that can show the phrase on a private screen.",
        ));
    }
    Ok(())
}

/// Runs the recovery's twelve rounds at the old settings. The old memory is released when it
/// returns, before the new settings reserve theirs.
fn recover(rekey: &Rekey, old_work: WorkFactor, how: &How) -> Result<RecoveredForRekey, Failure> {
    let mut mhfe = settings::reserve_memory(old_work)?;
    let reference = how.reference();
    let mut progress = Progress::start()?;
    // The terminal shows the twelve rounds of the recovery as before; a comparison with the
    // wallet follows them without a round of its own.
    let state = rekey.recover_state(
        &mut mhfe,
        how.confirmation(reference.as_ref()),
        &mut |stage, round, rounds| {
            if stage == Stage::Recover {
                progress.round_starts(stage, round, rounds);
            }
            Ok(())
        },
    );
    progress.finish();
    Ok(state?)
}

/// The phrase of `state`, once a confirmation confirms it: after a refusal that the library lets
/// another confirmation follow, the person chooses again, on the same recovery.
fn confirm(
    input: &mut Input,
    rekey: &mut Rekey,
    state: &RecoveredForRekey,
    how: &mut How,
    wallet_passphrase: bool,
    address_options: &check::AddressOptions,
) -> Result<ConfirmedPhrase, Failure> {
    let mut previous_refusal = None;
    let mut owner_words = None;
    loop {
        let reference = how.reference();
        let confirmation = how.confirmation(reference.as_ref());
        let mut progress = |_, _, _| Ok(());
        let confirmed = if let Some(refusal) = &previous_refusal {
            rekey.confirm_again(
                state,
                refusal,
                confirmation,
                owner_words,
                Some(wallet_passphrase),
                &mut progress,
            )
        } else {
            rekey.confirm(state, confirmation, Some(wallet_passphrase), &mut progress)
        };
        let refusal = match confirmed {
            Ok(confirmed) => return Ok(confirmed),
            Err(refusal) => refusal,
        };
        // Whether another confirmation may follow, and at which lengths the owner may give it, is
        // the library's to say (AUD-017-ARC002); any other refusal ends the rekey.
        let Some(owner_lengths) = rekey.owner_lengths_after(state, &refusal)? else {
            return Err(refusal.into());
        };
        style::retry_next(match refusal {
            // The built-in check finds another length than the one stated: it takes precedence,
            // and the wallet confirms the phrase (AUD-015-FUN001).
            MhfeError::LengthDiffers { stated, found } => format!(
                "{} {}, but the wallet must confirm the phrase.",
                phrase_length::check_finds(found, stated),
                phrase_length::MORE_RELIABLE
            ),
            // Several lengths pass, about once in four billion containers: the built-in check
            // cannot tell them apart, a stated length neither (the specification's re-encryption
            // rules). An address or the fingerprint compares every reading.
            _ => SEVERAL_LENGTHS.to_owned(),
        });
        let kind = if address_options.given_names().is_empty() {
            ask_how_to_confirm(input, !owner_lengths.is_empty())?
        } else {
            Kind::Address
        };
        // The owner compares the reading of one of these lengths, stated where there is a choice.
        owner_words = match (kind, &owner_lengths[..]) {
            (Kind::Owner, [_]) => None, // The library selects the only permitted length.
            (Kind::Owner, _) => Some(phrase_length::ask_stated(
                input,
                &owner_lengths,
                &[],
                "Phrase",
            )?),
            _ => None,
        };
        previous_refusal = Some(refusal);
        *how = how_of(input, kind, wallet_passphrase, address_options)?;
    }
}

/// Records how the recovered phrase was confirmed, after the owner's comparison where the owner
/// confirms it, and returns it ready to seal.
fn record_recovery(
    input: &mut Input,
    recovered: ConfirmedPhrase,
    how: &How,
) -> Result<ConfirmedPhrase, Failure> {
    let phrase = recovered.phrase();
    // The 16-bit source check of a 24-word reading, which every recovery evaluates, with the
    // passphrase typed for the reference or the empty one; only a pass is said. It never
    // confirms a phrase to seal again: 16 bits are too few.
    // Borrowed from its locked buffer, not copied (AUD-024-SEC013).
    let reference = how.reference();
    let source_passphrase = reference
        .as_ref()
        .and_then(mhfe::Reference::passphrase)
        .unwrap_or("");
    let source_check = match phrase.passes_wallet_check(source_passphrase)? {
        Some(true) => format!(", passes the {WALLET_CHECK_BITS}-bit check"),
        _ => String::new(),
    };
    let by_owner = matches!(how, How::Owner);
    let confirmed = match how {
        How::BuiltInCheck => "passed its built-in check",
        // A detected short phrase passed its built-in check as well.
        How::Wallet(_) if phrase.verified() => "passed its built-in check, matches the wallet",
        How::Wallet(_) => "matches the wallet",
        How::Owner => {
            if let Some(stated) = phrase.stated_words() {
                style::warn(&phrase_length::check_finds(phrase.words(), stated), "");
            }
            owner_confirms(input, phrase.phrase())?;
            if phrase.verified() {
                "passed its built-in check, confirmed by you"
            } else {
                "confirmed by you"
            }
        }
    };
    choice::record(
        "Recovered",
        &format!("{} words, {confirmed}{source_check}", phrase.words()),
    );
    // The owner said yes, explicitly: only now may the library seal the phrase.
    Ok(if by_owner {
        recovered.confirmed_by_owner()
    } else {
        recovered
    })
}

/// The reference the replacement's rehearsal compares, known before it is made (the
/// specification's re-encryption rules), with the wallet's passphrase where the library needs it.
fn replacement_rehearsal(
    input: &mut Input,
    recovered: &ConfirmedPhrase,
) -> Result<ReplacementRehearsal, Failure> {
    let passphrase = if recovered.rehearsal_needs_passphrase() {
        check::read_passphrase_named(input, Operation::Rekey, check::ORIGINAL_SEED_PHRASE)?
    } else {
        LockedText::copy_of("")
    };
    Ok(recovered.replacement_rehearsal(&passphrase)?)
}

/// Seals the phrase by the library's rekey, which the browser package and the checks at start run
/// too: a container of the old one's kind, and new settings or a new password that change it
/// (AUD-010). The terminal shows it as any encryption.
fn seal(
    input: &Input,
    rekey: &Rekey,
    recovered: &ConfirmedPhrase,
    new_password: &Password,
    new_work: WorkFactor,
    repair_count: Option<usize>,
) -> Result<Sealed, Failure> {
    let mut mhfe = settings::reserve_memory(new_work)?;
    encrypt::show_sealing(input, Operation::Rekey, |progress, on_unverified| {
        rekey.seal(
            &mut mhfe,
            recovered,
            new_password,
            repair_count,
            progress,
            on_unverified,
        )
    })
}

/// The summary at the end: the new container's format, what to keep, the old backup, and the
/// rehearsal to do next.
fn print_summary(
    new: &Sealed,
    new_work: WorkFactor,
    recovered: &ConfirmedPhrase,
    rehearsal: &ReplacementRehearsal,
) {
    encrypt::print_container_summary(new, new_work, recovered.wallet_has_passphrase().into());
    // Rekeying revokes nothing: the old container phrase and password open the wallet until
    // destroyed.
    style::fact(
        "Old backup",
        "the old container phrase still opens the wallet with the old password",
    );
    style::fact("Next", next_rehearsal(rehearsal));
    if matches!(rehearsal, ReplacementRehearsal::Fingerprint(_)) {
        style::fingerprint_fact();
    }
    style::more(readme::REKEY);
}

/// What the summary says to do next: rehearse the new container phrase, with the fingerprint the
/// library names where the owner confirmed the phrase alone.
fn next_rehearsal(rehearsal: &ReplacementRehearsal) -> String {
    match rehearsal {
        ReplacementRehearsal::Fingerprint(fingerprint) => format!(
            "rehearse the new container phrase with {} and fingerprint {}",
            paint(ACCENT, "mhfe check --fingerprint"),
            paint(ACCENT, fingerprint_text(*fingerprint))
        ),
        ReplacementRehearsal::BuiltInCheck | ReplacementRehearsal::ConfirmingReference => format!(
            "rehearse the new container phrase with {}",
            paint(ACCENT, "mhfe check")
        ),
    }
}

/// How a recovery is confirmed before it is encrypted again.
enum How {
    BuiltInCheck,
    Wallet(WalletReference),
    Owner,
}

impl How {
    /// The wallet's reference, for an address or the fingerprint.
    fn reference(&self) -> Option<mhfe::Reference<'_>> {
        match self {
            Self::Wallet(wallet) => Some(wallet.reference()),
            Self::BuiltInCheck | Self::Owner => None,
        }
    }

    /// The library's confirmation, with `reference` from [`How::reference`].
    fn confirmation<'a>(&self, reference: Option<&'a mhfe::Reference<'a>>) -> Confirmation<'a> {
        match (self, reference) {
            (Self::Wallet(_), Some(reference)) => Confirmation::Wallet(reference),
            (Self::Owner, _) => Confirmation::Owner,
            _ => Confirmation::BuiltInCheck,
        }
    }
}

/// The confirmation of `kind`, its reference read for an address or the fingerprint, of a wallet
/// whose BIP39 passphrase the person has said it has or has not.
fn how_of(
    input: &mut Input,
    kind: Kind,
    wallet_passphrase: bool,
    address_options: &check::AddressOptions,
) -> Result<How, Failure> {
    Ok(match kind {
        Kind::BuiltInCheck => How::BuiltInCheck,
        Kind::Owner => How::Owner,
        Kind::Address | Kind::Fingerprint => How::Wallet(WalletReference::read_of_wallet(
            input,
            kind == Kind::Fingerprint,
            Operation::Rekey,
            wallet_passphrase,
            address_options,
        )?),
    })
}

/// The kind of confirmation chosen, before its reference is read; `--confirm` names it too.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Kind {
    #[value(name = "check")]
    BuiltInCheck,
    Address,
    Fingerprint,
    #[value(name = "show")]
    Owner,
}

/// The warning about the wallets other passwords open on the old container, one plain sentence
/// (the owner's wording of 2026-10-09, the specification's), naming what the library says to keep
/// of the old container ([`Keep::old_container`]).
fn keep_until_funds_moved(old_work: WorkFactor) -> String {
    format!(
        "Wallets that other passwords open on the old container do not move to the new one: keep \
         {} until you have moved their funds.",
        encrypt::what_to_keep(&Keep::old_container(old_work))
    )
}

/// For a recovery without a built-in check, one whose length is detected, or one whose built-in
/// check contradicts the stated length: a receiving address, the fingerprint, or, `with_owner`,
/// the phrase shown to the owner, who compares it with their backup. A detected 12- to 21-word
/// phrase passes its built-in check as well.
fn ask_how_to_confirm(input: &mut Input, with_owner: bool) -> Result<Kind, Failure> {
    let mut kinds = vec![Kind::Address, Kind::Fingerprint];
    let mut answers = Vec::from(check::wallet_answers());
    // The phrase is shown only on a private screen, so it is offered only where there can be one
    // (AUD-007-SEC001). Said before it appears: a comparison from memory confirms little.
    if with_owner && terminal::can_show_privately(input) {
        kinds.push(Kind::Owner);
        // Only for an owner who knows neither an address nor the fingerprint (the specification's
        // re-encryption rules), which the answer says.
        answers.push(Answer::new(
            "I know neither: show me the phrase",
            "compare it with a written record or enter it into your wallet",
        ));
    }
    let question = Question::new(
        "How should the recovered seed phrase be confirmed?",
        "Confirm",
    );
    Ok(kinds[input.choose(&question, &answers)?])
}

/// Why a rekey asks about the passphrase, under the question: a person may well wonder why a tool
/// that encrypts a phrase asks about a passphrase at all.
const ASKS_WHY: &[&str] = &[
    "Asked so that the list of what to keep at the end is complete:",
    "MHFE stores no passphrase. It asks for one only to compare an address",
    "or a fingerprint, or for the fingerprint to rehearse the new container.",
];

/// Asks whether the wallet of the phrase has a BIP39 passphrase, which the keep list at the end
/// names: MHFE encrypts the phrase, not the passphrase. A wallet with one is asked for it to
/// compare an address or a fingerprint, or for the fingerprint that rehearses the new container.
fn ask_wallet_passphrase(input: &mut Input) -> Result<bool, Failure> {
    let answers = [
        Answer::new("No BIP39 passphrase", "the phrase alone opens the wallet"),
        Answer::new(
            "It has a BIP39 passphrase",
            "keep it too: MHFE does not store it",
        ),
    ];
    let question = Question {
        text: "Does the wallet of this phrase have a BIP39 passphrase?",
        explanation: ASKS_WHY,
        more: Some(readme::REKEY),
        record: Some("Passphrase"),
    };
    // No answer is the default: a hurried Enter must not leave the passphrase out of what to keep.
    Ok(input.choose_without_default(&question, &answers)? == 1)
}

/// How the owner checks the phrase shown, under the question.
const OWNER_CHECKS: &[&str] = &[
    "Compare it with your written record, or enter it into your wallet and",
    "check that it shows your addresses. Nothing goes on until you choose.",
];

/// Shows the recovered phrase on a private screen and asks the owner whether it is theirs. Only a
/// yes goes on; the screen is cleared either way.
fn owner_confirms(input: &mut Input, phrase: &str) -> Result<(), Failure> {
    let screen = terminal::PrivateScreen::enter_to_show(input)?;
    if !screen.shows_privately() {
        return Err(Failure::internal(
            "No private screen to show the phrase on.",
        ));
    }
    if screen.is_active() {
        style::title(Operation::Rekey.title());
    }
    eprintln!();
    eprintln!("{}", paint(HEADING, "Recovered seed phrase"));
    terminal::print_phrase(phrase, Wallet::NoPassphrase, input)?;
    let question = Question {
        text: "Does it match your written record, word for word?",
        explanation: OWNER_CHECKS,
        more: None,
        record: None,
    };
    let answers = [
        Answer::new("Yes, every word", ""),
        Answer::new("No, stop", "nothing is encrypted again"),
    ];
    // Asked below the phrase, which stays on the screen until the answer. No answer is marked:
    // the confirmation must be explicit, so a hurried Enter does nothing (the specification's
    // re-encryption rules).
    let mine = input.choose_here_without_default(&question, &answers)? == 0;
    drop(screen);
    if mine {
        Ok(())
    } else {
        Err(MhfeError::NotConfirmedByOwner.into())
    }
}

/// The length of the seed phrase, which the owner states: a same-length container has its own,
/// and for a 24-word container it comes from --words or is asked. The built-in check of a short
/// phrase is taken at that length only. A length given with --words is checked before the
/// password is asked: one that no phrase has, or one that contradicts a same-length container, is
/// refused (AUD-008-FUN002).
fn phrase_length(
    input: &mut Input,
    given: Option<PhraseLength>,
    container: &ContainerFacts,
) -> Result<PhraseLength, Failure> {
    if let Some(given) = given {
        // Only its refusal matters here, of a length that a same-length container cannot have:
        // the confirmation itself is chosen once the password is typed.
        container.require_length(given)?;
        return Ok(given);
    }
    let lengths = container.phrase_lengths();
    if let [only] = lengths {
        return Ok(PhraseLength::Words(WordCount::new(*only)?));
    }
    phrase_length::ask(input, lengths, DETECTION_MISSES, "Phrase")
}

/// What detection asks for in a rekey, beside its answer: the built-in check alone confirms no
/// detected length, so an address, the fingerprint or the phrase shown confirms it, as for 24
/// words.
pub(crate) const DETECTION_MISSES: &str = "then an address or the phrase confirms";

/// Said when several lengths pass, before the question how to confirm the phrase.
const SEVERAL_LENGTHS: &str =
    "Several lengths pass the built-in check, by rare chance. A receiving \
                               address or the master key fingerprint tells them apart.";

/// The new password, typed twice. With the same settings it must differ from the old one: the
/// same password would give the same container again.
fn read_different_password(
    input: &mut Input,
    rekey: &Rekey,
    new_work: WorkFactor,
    kind: Option<PasswordKind>,
) -> Result<Password, Failure> {
    loop {
        let new = encrypt::read_new_password(input, Operation::Rekey, kind)?;
        match rekey.check_new(&new, new_work) {
            Ok(()) => return Ok(new),
            Err(MhfeError::NewPasswordSameAsOld) => {
                // Said where the new password is typed again.
                style::retry_next(
                    "This is the old password, which gives the old container. Choose another.",
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_repair_words_skip_the_question_without_recovering_the_old_container() {
        use clap::Parser;
        for (typed, expected) in [("0", None), ("4", Some(4))] {
            let cli =
                crate::Cli::try_parse_from(["mhfe", "rekey", "--repair-words", typed]).unwrap();
            let crate::Command::Rekey(options) = cli.command else {
                unreachable!()
            };
            let mut input = Input::terminal_only();
            assert_eq!(options.repair_words.choose(&mut input).unwrap(), expected);
        }
    }
    use mhfe::WORD_COUNTS;

    #[test]
    fn the_warning_names_settings_that_are_not_the_defaults() {
        let keep = |pim, level| keep_until_funds_moved(WorkFactor::new(pim, level).unwrap());
        assert_eq!(
            keep(0, 0),
            "Wallets that other passwords open on the old container do not move to the new one: \
             keep the old container and its passwords until you have moved their funds."
        );
        assert!(keep(3, 0).contains("keep the old container, its passwords and PIM 3 until"));
        assert!(keep(0, 2).contains("the old container, its passwords and memory level 2 until"));
        assert!(keep(3, 2).contains("container, its passwords, PIM 3 and memory level 2 until"));
    }

    #[test]
    fn why_the_passphrase_is_asked_fits_the_list() {
        assert!(choice::fits(ASKS_WHY));
    }

    /// AUD-008-FUN002: a length given for a same-length container must be its own, and a length
    /// that no phrase has is refused, both before the password is asked.
    #[test]
    fn a_length_given_must_fit_the_container() {
        let mut input = Input::terminal_only();
        // A container of `words` words: a valid phrase of all-zero entropy, as in BIP39's vectors.
        let container = |words: usize| {
            let entropy = vec![0; WordCount::new(words).unwrap().entropy_bytes()];
            let phrase = mhfe::phrase_from_entropy(&entropy).unwrap();
            ContainerFacts::read(&phrase).unwrap()
        };
        let stated = |count| PhraseLength::Words(WordCount::new(count).unwrap());
        let length = |input: &mut Input, given: Option<PhraseLength>, words| {
            phrase_length(input, given, &container(words)).ok()
        };
        for words in [12, 15, 18, 21] {
            assert_eq!(length(&mut input, None, words), Some(stated(words)));
            for given in [stated(words), PhraseLength::Detect] {
                assert_eq!(length(&mut input, Some(given), words), Some(given));
            }
            for other in WORD_COUNTS.into_iter().filter(|&other| other != words) {
                let refused =
                    phrase_length(&mut input, Some(stated(other)), &container(words)).unwrap_err();
                assert!(
                    refused.message.contains("keeps the length"),
                    "{}",
                    refused.message
                );
            }
        }
        for given in WORD_COUNTS
            .map(stated)
            .into_iter()
            .chain([PhraseLength::Detect])
        {
            assert_eq!(length(&mut input, Some(given), 24), Some(given));
        }
        // A length that no phrase has is refused as --words is read.
        for impossible in ["13", "25"] {
            assert!(phrase_length::parse(impossible).is_err());
        }
    }
}
