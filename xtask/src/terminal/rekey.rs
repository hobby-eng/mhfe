//! `mhfe rekey`: the warning about other wallets on the old container, and the question about the
//! wallet's BIP39 passphrase, as a list with no default and as numbered answers.

use super::password::shown_privately;
use super::session::{Session, Start, capped_here, contains, count, find, rfind, shown};
use super::text::{without_controls, without_hints, words};
use super::{
    ANY_PASSPHRASE_ASKED, CANCELLED, CLEAR, CONTAINER_ASKED, CTRL_C, DOWN, ENTER, ESCAPE,
    HIGHLIGHT, KNOWN_PASSPHRASE_ASKED, LIST_SHOWN, MEMORY_REFUSED, NOT_ENOUGH_RESOURCES,
    NUMBERED_PROMPT, PASSPHRASE_ASKED, PASSPHRASE_RECORD, PUBLIC_PASSPHRASE, SECRET, UP, container,
    ensure, join,
};
use crate::Failure;

/// The two answers about the passphrase, neither of them a default, and the record of each.
const PASSPHRASE_ANSWERS: [&[u8]; 2] = [b"1  No BIP39 passphrase", b"2  It has a BIP39 passphrase"];
const NO_PASSPHRASE_RECORDED: &[u8] = b"Passphrase No BIP39 passphrase";
const PASSPHRASE_RECORDED: &[u8] = b"Passphrase It has a BIP39 passphrase";
/// The key hint of that list while no answer is marked, and once an arrow has marked one (hint in
/// src/bin/mhfe/choice.rs).
const UNMARKED_HINT: &str =
    "↑ ↓ choose · Enter selects once one is marked · 1 or 2 at once · Esc cancels";
const MARKED_HINT: &str = "↑ ↓ choose · Enter selects · 1 or 2 at once · Esc cancels";
/// How long the tool is watched after a key that must do nothing; it answers a key at once.
const QUIET_SECONDS: f64 = 1.0;
/// Why a rekey asks about the passphrase, the lines under the question (ASKS_WHY in
/// src/bin/mhfe/rekey.rs).
const PASSPHRASE_WHY: [&str; 3] = [
    "Asked so that the list of what to keep at the end is complete:",
    "MHFE stores no passphrase. It asks for one only to compare an address",
    "or a fingerprint, or for the fingerprint to rehearse the new container.",
];
const PASSPHRASE_REFUSED: &[u8] = b"Type the passphrase: you said the wallet has one.";
const CONFIRMATION_ASKED: &[u8] = b"How should the recovered seed phrase be confirmed?";
const COIN_ASKED: &[u8] = b"Which coin is the address for?";
const ADDRESS_ASKED: &[u8] = b"Receiving address (";
const FINGERPRINT_ASKED: &[u8] = b"Master key fingerprint, eight hex digits: ";
const REKEY_TITLE: &[u8] = "MHFE · Change the password".as_bytes();
/// A reference of the wallet: the first receiving address of BIP84's test vectors, a public one,
/// and the master key fingerprint of the public zero-12 phrase. Argon2 never runs here, so
/// neither is ever compared with a recovered phrase.
const PUBLIC_ADDRESS: &[u8] = b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const PUBLIC_FINGERPRINT: &[u8] = b"73c5da0a";
/// The numbered answers at a terminal that cannot redraw a list, and the refusal of a number.
const NUMBERED_ANSWERS: [&[u8]; 2] = [b"1. No BIP39 passphrase", b"2. It has a BIP39 passphrase"];
const NUMBERED_REFUSED: &[u8] = b"Type a number from 1 to 2.";

pub(super) fn run() -> Result<(), Failure> {
    warns_about_other_wallets()?;
    asks_about_the_passphrase()?;
    a_dumb_terminal_numbers_the_answers()
}

/// `mhfe rekey` asks nothing about other wallets on the container: every user gets a warning at
/// the top of the container prompt that they do not move to the new container, and that the old
/// one and its passwords are kept until their funds are moved; a PIM that is not the default is
/// named among them. No password is asked before it.
fn warns_about_other_wallets() -> Result<(), Failure> {
    for (pim, warning) in [
        (
            "0",
            "Wallets that other passwords open on the old container do not move to the new one: \
             keep the old container and its passwords until you have moved their funds.",
        ),
        (
            "2",
            "keep the old container, its passwords and PIM 2 until you have moved their funds.",
        ),
    ] {
        let label = format!("rekey --pim {pim}");
        let mut session = Session::of(&["rekey", "--pim", pim, "--mem", "0", "--words", "24"])?;
        session.wait(CONTAINER_ASKED)?;
        session.ends_with(CANCELLED, &label)?;
        let end = find(&session.output, CONTAINER_ASKED, 0).unwrap_or(session.output.len());
        let before = without_controls(&session.output[..end]);
        // Each wrapped line of a warning starts with its "!": compare the words.
        let lines: Vec<String> = String::from_utf8_lossy(&before)
            .replace('\r', "")
            .lines()
            .map(|line| line.strip_prefix("! ").unwrap_or(line).to_owned())
            .collect();
        let said = words(lines.join("\n").as_bytes());
        ensure(said.contains(warning), || {
            format!("{label}: {warning:?} is not shown above the container prompt")
        })?;
        ensure(
            !contains(&session.output, b"backed up another way?"),
            || format!("{label}: the old question was asked"),
        )?;
        ensure(!contains(&before, b"Password"), || {
            format!("{label}: a password was asked first")
        })?;
        println!(
            "{label}: the warning about other wallets heads the container prompt, nothing is asked"
        );
    }
    Ok(())
}

/// The question about the wallet's passphrase as a terminal shows it: the reason it is asked,
/// indented, then after a blank line the link to the README section of `mhfe rekey`.
fn passphrase_question() -> Vec<u8> {
    let why: String = PASSPHRASE_WHY
        .iter()
        .map(|line| format!("\r\n  {line}"))
        .collect();
    join(&[
        PASSPHRASE_ASKED,
        why.as_bytes(),
        b"\r\n\r\n  More: https://github.com/hobby-eng/mhfe#mhfe-rekey",
    ])
}

/// The question about the passphrase, just shown as a list, has no answer marked and a hint that
/// says so, and Enter alone leaves it as it is: nothing is redrawn, erased or recorded.
pub(super) fn has_no_default(
    label: &str,
    session: &mut Session,
    question: &[u8],
    hint: &str,
) -> Result<(), Failure> {
    let at = rfind(&session.output, question).unwrap_or(0);
    // The whole list first, up to the line break after its key hint, the last thing it writes:
    // the hint of a list shown before may have passed for it.
    session.wait_for(&[&join(&[LIST_SHOWN, b"\r\n"])], 10, Some(at))?;
    let shown_list = session.output[at..].to_vec();
    ensure(!contains(&shown_list, HIGHLIGHT), || {
        format!("{label}: an answer was marked")
    })?;
    let framed = format!("\r\n{hint}\r\n");
    ensure(contains(&shown_list, framed.as_bytes()), || {
        format!("{label}: the hint is not {hint:?}")
    })?;
    let written = session.idle(ENTER, QUIET_SECONDS)?;
    ensure(written.is_empty(), || {
        format!(
            "{label}: Enter alone answered the question: {}",
            shown(&written)
        )
    })
}

/// Starts `mhfe rekey` for a phrase of `words` words, with the address space capped when
/// `capped`, and answers up to the old container password.
fn rekey_at_old_password(words: &str, capped: bool) -> Result<Session, Failure> {
    let arguments = ["rekey", "--pim", "0", "--words", words];
    let mut session = Session::start(Start {
        capped,
        ..Start::of(&arguments)
    })?;
    session.wait(CONTAINER_ASKED)?;
    session.answer(
        format!("{}\r", container()).as_bytes(),
        &[b"container password: "],
    )?;
    Ok(session)
}

/// The question about the passphrase is the next screen after the keys typed at `since`: only
/// `typed`, the cleared screen and the title of the step come in between. No reference of the
/// wallet, passphrase or memory for the long work was asked for before it.
fn asked_next(label: &str, session: &Session, since: usize, typed: &[u8]) -> Result<(), Failure> {
    let question = find(&session.output, PASSPHRASE_ASKED, since).unwrap_or(session.output.len());
    let mut between = without_controls(&without_hints(&session.output[since..question]));
    for part in [typed, REKEY_TITLE] {
        if !part.is_empty() {
            while let Some(at) = find(&between, part, 0) {
                between.drain(at..at + part.len());
            }
        }
    }
    ensure(between.iter().all(u8::is_ascii_whitespace), || {
        format!(
            "rekey, {label}: {} before the passphrase question",
            shown(&between)
        )
    })?;
    for prompt in [
        COIN_ASKED,
        ADDRESS_ASKED,
        FINGERPRINT_ASKED,
        ANY_PASSPHRASE_ASKED,
        MEMORY_REFUSED,
    ] {
        ensure(!contains(&session.output[..question], prompt), || {
            format!(
                "rekey, {label}: {} came before the passphrase question",
                shown(prompt)
            )
        })?;
    }
    Ok(())
}

/// The kinds of confirmation of a rekey.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    BuiltInCheck,
    ShowingThePhrase,
    Address,
    Fingerprint,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::BuiltInCheck => "the built-in check",
            Self::ShowingThePhrase => "showing the phrase",
            Self::Address => "an address",
            Self::Fingerprint => "the fingerprint",
        }
    }
}

/// A rekey of a phrase of `words` words confirmed by `kind`: the keys that choose the
/// confirmation, if it is asked; the key that marks an answer about the passphrase before it is
/// taken, if any; the keys that take it; and whether the wallet has a passphrase.
struct Case {
    kind: Kind,
    words: &'static str,
    confirmation: Option<&'static [u8]>,
    mark: Option<&'static [u8]>,
    select: &'static [u8],
    has_one: bool,
}

impl Case {
    const fn of(
        kind: Kind,
        words: &'static str,
        confirmation: Option<&'static [u8]>,
        mark: Option<&'static [u8]>,
        select: &'static [u8],
        has_one: bool,
    ) -> Self {
        Self {
            kind,
            words,
            confirmation,
            mark,
            select,
            has_one,
        }
    }
}

/// Answers the question about the passphrase with the keys `select` and types the reference of
/// the wallet that the confirmation `kind` needs, if any; `then` is what the tool shows after the
/// last of these keys.
fn give_the_reference(
    session: &mut Session,
    kind: Kind,
    select: &[u8],
    then: &[&[u8]],
) -> Result<(), Failure> {
    let address = join(&[PUBLIC_ADDRESS, b"\r"]);
    let fingerprint = join(&[PUBLIC_FINGERPRINT, b"\r"]);
    match kind {
        Kind::Address => {
            // Bitcoin, the first coin, is marked at the start: Enter takes it.
            session.answer(select, &[COIN_ASKED, LIST_SHOWN])?;
            session.answer(ENTER, &[ADDRESS_ASKED])?;
            session.answer(&address, then)
        }
        Kind::Fingerprint => {
            session.answer(select, &[FINGERPRINT_ASKED])?;
            session.answer(&fingerprint, then)
        }
        _ => session.answer(select, then),
    }
}

/// The capped rekey went on to the long work and was refused its memory, before Argon2; returns
/// the summary on the main screen.
fn ended_before_argon2(label: &str, session: &mut Session) -> Result<Vec<u8>, Failure> {
    // The refusal is written once, at the end; it may have been read with the last answer already.
    session.wait_for(&[MEMORY_REFUSED], 10, Some(0))?;
    ensure(session.drain_until_exit(10), || {
        format!("rekey, {label}: the refusal did not end the tool")
    })?;
    session.ends_with(NOT_ENOUGH_RESOURCES, &format!("rekey, {label}"))?;
    Ok(session.summary().to_vec())
}

/// The question about the wallet's passphrase comes once, right after the kind of confirmation is
/// known, for every kind and before any reference or passphrase is read (multi-chain-wallet-tools
/// AUD-022-API004). Only a wallet with a passphrase is then asked for it, and only with an address
/// or the fingerprint; it may not be empty there.
fn asks_about_the_passphrase() -> Result<(), Failure> {
    let capped = capped_here();
    let question = passphrase_question();
    // On a screen of its own, as every step.
    let asked: [&[u8]; 5] = [
        CLEAR,
        &question,
        PASSPHRASE_ANSWERS[0],
        PASSPHRASE_ANSWERS[1],
        LIST_SHOWN,
    ];
    let cases = [
        // A 12-word phrase has a built-in check: nothing is chosen after the password. ↓ marks
        // the first answer, which Enter then takes.
        Case::of(Kind::BuiltInCheck, "12", None, Some(DOWN), ENTER, false),
        // A digit chooses at once.
        Case::of(Kind::ShowingThePhrase, "24", Some(b"3"), None, b"2", true),
        Case::of(Kind::Address, "24", Some(b"1"), None, b"1", false),
        // ↑ marks the last answer.
        Case::of(Kind::Address, "24", Some(b"1"), Some(UP), ENTER, true),
        Case::of(
            Kind::Fingerprint,
            "24",
            Some(b"2"),
            Some(DOWN),
            ENTER,
            false,
        ),
        Case::of(Kind::Fingerprint, "24", Some(b"2"), None, b"2", true),
    ];
    for Case {
        kind,
        words,
        confirmation,
        mark,
        select,
        has_one,
    } in cases
    {
        let label = format!(
            "{}, {} a passphrase",
            kind.name(),
            if has_one { "with" } else { "without" }
        );
        let answer = PASSPHRASE_ANSWERS[usize::from(has_one)];
        let record = if has_one {
            PASSPHRASE_RECORDED
        } else {
            NO_PASSPHRASE_RECORDED
        };
        // Only a reference of the wallet is compared with a passphrase.
        let asks_for_it = has_one && matches!(kind, Kind::Address | Kind::Fingerprint);
        let mut session = rekey_at_old_password(words, capped)?;
        let password = join(&[SECRET, b"\r"]);
        match confirmation {
            None => {
                let start = session.output.len();
                session.answer(&password, &asked)?;
                asked_next(&label, &session, start, SECRET)?;
            }
            Some(confirmation) => {
                session.answer(&password, &[CONFIRMATION_ASKED, LIST_SHOWN])?;
                let start = session.output.len();
                session.answer(confirmation, &asked)?;
                asked_next(&label, &session, start, b"")?;
            }
        }
        has_no_default(
            &format!("rekey, {label}"),
            &mut session,
            PASSPHRASE_ASKED,
            UNMARKED_HINT,
        )?;
        if let Some(mark) = mark {
            session.answer(
                mark,
                &[&join(&[HIGHLIGHT, b" ", answer]), MARKED_HINT.as_bytes()],
            )?;
        }
        if !capped {
            session.answer(ESCAPE, &[b"Cancelled"])?;
            session.ends_with(CANCELLED, &format!("rekey, {label}: Escape"))?;
            println!("rekey, {label}: asked, none marked; Escape stops, exit code 130");
            continue;
        }
        let then: &[u8] = if asks_for_it {
            KNOWN_PASSPHRASE_ASKED
        } else {
            MEMORY_REFUSED
        };
        give_the_reference(&mut session, kind, select, &[then])?;
        if asks_for_it {
            session.answer(b"\r", &[PASSPHRASE_REFUSED, KNOWN_PASSPHRASE_ASKED])?;
            session.answer(&join(&[PUBLIC_PASSPHRASE, b"\r"]), &[MEMORY_REFUSED])?;
        }
        let summary = ended_before_argon2(&label, &mut session)?;
        if asks_for_it {
            ensure(!contains(&session.output, b"if it has none"), || {
                format!("rekey, {label}: Enter for none")
            })?;
            shown_privately(
                &format!("rekey, {label}"),
                &session.output,
                PUBLIC_PASSPHRASE,
            )?;
        } else {
            ensure(!contains(&session.output, ANY_PASSPHRASE_ASKED), || {
                format!("rekey, {label}: asked for a passphrase")
            })?;
        }
        ensure(contains(&summary, record), || {
            format!("rekey, {label}: the summary lacks {}", shown(record))
        })?;
        let records = count(
            &summary
                .iter()
                .filter(|byte| **byte != b'\r')
                .copied()
                .collect::<Vec<_>>(),
            PASSPHRASE_RECORD,
        );
        ensure(records == 1, || {
            format!("rekey, {label}: {records} Passphrase records, not one")
        })?;
        ensure(!contains(&summary, PASSPHRASE_ASKED), || {
            format!("rekey, {label}: the question reached the summary")
        })?;
        recorded_where_asked(&label, &summary, record, kind, confirmation.is_some())?;
        let after = if asks_for_it {
            "an empty passphrase refused"
        } else {
            "no passphrase prompt after it"
        };
        println!("rekey, {label}: asked first, none marked; {after}");
    }
    if capped {
        println!(
            "rekey: one Passphrase record each, in the order asked; each stopped before Argon2"
        );
    }
    Ok(())
}

/// The answer about the passphrase is recorded where it was asked: after the choice of the
/// confirmation, when one was `chosen`, and before the reference of the wallet.
fn recorded_where_asked(
    label: &str,
    summary: &[u8],
    record: &[u8],
    kind: Kind,
    chosen: bool,
) -> Result<(), Failure> {
    let place = find(summary, record, 0).unwrap_or(0);
    if chosen {
        let confirm = find(summary, b"  Confirm ", 0);
        ensure(confirm.is_some_and(|confirm| confirm < place), || {
            format!("rekey, {label}: the answer is not recorded after the confirmation")
        })?;
    }
    let first_of_reference: Option<&[u8]> = match kind {
        Kind::Address => Some(b"  Coin "),
        Kind::Fingerprint => Some(b"  Master key "),
        _ => None,
    };
    if let Some(first) = first_of_reference {
        ensure(find(summary, first, 0).is_some_and(|at| place < at), || {
            format!("rekey, {label}: the answer is not recorded before the reference")
        })?;
    }
    Ok(())
}

/// A terminal that cannot redraw a list gets the question about the passphrase with numbered
/// answers and a prompt without a default; an empty line, or a number out of range, is refused
/// and the prompt asked again. A 12-word phrase has a built-in check, so the question follows the
/// hidden old password. On Linux the capped run takes 2 and stops at the memory reservation,
/// before Argon2; elsewhere Ctrl+C at the prompt ends it.
fn a_dumb_terminal_numbers_the_answers() -> Result<(), Failure> {
    let capped = capped_here();
    let arguments = ["rekey", "--pim", "0", "--words", "12"];
    let mut session = Session::start(Start {
        term: "dumb",
        capped,
        ..Start::of(&arguments)
    })?;
    session.wait(CONTAINER_ASKED)?;
    session.answer(
        format!("{}\r", container()).as_bytes(),
        &[b"Old container password (hidden): "],
    )?;
    session.answer(
        &join(&[SECRET, b"\r"]),
        &[
            PASSPHRASE_ASKED,
            NUMBERED_ANSWERS[0],
            NUMBERED_ANSWERS[1],
            NUMBERED_PROMPT,
        ],
    )?;
    let at = rfind(&session.output, PASSPHRASE_ASKED).unwrap_or(0);
    ensure(!contains(&session.output[at..], b"[1]"), || {
        "rekey, TERM=dumb: the prompt offers a default".to_owned()
    })?;
    for typed in [&b""[..], b"3"] {
        session.answer(&join(&[typed, b"\r"]), &[NUMBERED_REFUSED, NUMBERED_PROMPT])?;
    }
    let (expected, ending) = if capped {
        session.answer(b"2\r", &[MEMORY_REFUSED])?;
        (
            NOT_ENOUGH_RESOURCES,
            "2 taken, stopped at the memory reservation",
        )
    } else {
        session.answer(CTRL_C, &[b"Cancelled"])?;
        (CANCELLED, "Ctrl+C at the prompt ends it")
    };
    ensure(session.drain_until_exit(10), || {
        "rekey, TERM=dumb: the tool did not end".to_owned()
    })?;
    session.ends_with(expected, "rekey, TERM=dumb")?;
    ensure(!contains(&session.output, SECRET), || {
        "rekey, TERM=dumb: the password was shown".to_owned()
    })?;
    println!(
        "rekey, TERM=dumb: numbered answers, \"Choice: \" without a default, the password hidden"
    );
    println!("rekey, TERM=dumb: an empty line and a number out of range refused; {ending}");
    Ok(())
}
