//! Repair words where a container phrase is read and in `mhfe repair`, the detection of the
//! original's length, the search for missing words, and the phrase + passphrase check of
//! `mhfe check`.

use super::password::shown_privately;
use super::session::{Session, capped_here, code, contains, run_plainly, shown};
use super::{
    CANCELLED, CONTAINER_ASKED, CTRL_C, INVALID_INPUT, KNOWN_PASSPHRASE_ASKED, LIST_SHOWN,
    MEMORY_REFUSED, NOT_ENOUGH_RESOURCES, PUBLIC_PASSPHRASE, SECRET, container, ensure, join,
    phrase,
};
use crate::Failure;

/// The repair of a container phrase where it is read (container_repair::review in the tool): the
/// card asked for, the repaired container phrase shown, and the question before it is used. The
/// card is the published four-word card of zero-12's container phrase (vectors/profiles).
const CARD_HINT: &[u8] =
    b"Type the repair words as written on the card; ? for a word you cannot read.";
pub(super) const CARD_ASKED: &[u8] = b"Repair words: ";
const ZERO_12_CARD: &[u8] = b"shaft pupil patient jewel";
const REPAIRED_HEADING: &[u8] = b"Repaired container phrase, 24 words";
const REPAIRED_SHOWN: &[u8] = b"Repaired words 3 and 17 of the container phrase.";
const USE_ASKED: &[u8] = b"Use the repaired container phrase?";
const REPAIR_OFFERED: &[u8] = b"Type the container phrase again, or repair it?";
const REPAIRED_RECORDED: &[u8] =
    b"Repaired   words 3 and 17 of the container phrase, with its repair words";
/// `mhfe repair` shows the repaired container phrase on a private screen.
const REPAIR_RESULT: &[u8] = b"Repaired container, 24 words";
const WRITE_IT_DOWN: &[u8] = super::WRITE_IT_DOWN;
/// The question of `mhfe check` about the reference, the place of "The phrase + passphrase check"
/// for a 24-word container whose original may be shorter, and what an empty passphrase gets there.
const COMPARE_ASKED: &[u8] = b"What should the recovered seed phrase be compared with?";
const WALLET_CHECK_ENTRY: &[u8] = b"4";
const WALLET_CHECK_REFUSED: &[u8] =
    b"Type the passphrase: the phrase + passphrase check needs one.";
/// The length of the original seed phrase detected: the last answer of the question about the
/// length, in check and rekey.
const LENGTH_ASKED: &[u8] = b"How many words does your original seed phrase have?";
const DETECT_OFFERED: &[u8] = b"Detect automatically";
const ORIGINAL_PASSPHRASE_ASKED: &[u8] =
    b"Is a BIP39 passphrase used with the original seed phrase?";
const CONFIRMATION_ASKED: &[u8] = b"How should the recovered seed phrase be confirmed?";
/// The search for missing words without the repair words (container_search.rs in the tool). The
/// decoy fingerprint of zero-12's container phrase, computed by an independent Python
/// implementation (src/search/known_answers.rs), finds its last word in seconds.
pub(super) const SEARCH_ASKED: &[u8] = b"No repair words: what do you know?";
pub(super) const REFERENCE_ASKED: &[u8] = b"Address or master key fingerprint: ";
const CONTAINER_PASSPHRASE_ASKED: &[u8] = b"Is a BIP39 passphrase used with the container phrase?";
const CONTAINER_PASSPHRASE_TYPED: &[u8] = b"BIP39 passphrase of the container phrase: ";
const NOT_IN_CONTAINER_WALLET: &[u8] = b"The container's own wallet does not match";
const ZERO_12_DECOY_FINGERPRINT: &[u8] = b"487a156e";
const FOUND_SHOWN: &[u8] = b"Found word 24: peace, by the 32-bit fingerprint";
const FOUND_USE_ASKED: &[u8] = b"Use the found container phrase?";
const FOUND_RECORDED: &[u8] = b"Repaired   word 24 of the container phrase, found by a search";
const LONG_SEARCH_WARNED: &[u8] =
    b"8 candidates, each a full recovery: about 8 to 16 minutes at these";
const TWO_EXPLAINED: &[u8] = b"Two words are missing: only a fingerprint or an address of the";
/// A nested SegWit address of zero-12's container phrase as a wallet, at m/49'/0'/0'/0/9, derived
/// by an independent Python implementation of BIP32 and P2SH-P2WPKH.
const ZERO_12_DECOY_ADDRESS: &[u8] = b"3FWJwUxDaXoGrxZQHT4EHBDZCZw7iHUaRn";
const GAP_ASKED: &[u8] = b"How far does the wallet go?";
const TWO_FOUND: &[u8] = b"Found word 5: iron, word 16: nerve, with the container's own wallet.";

pub(super) fn run() -> Result<(), Failure> {
    wallet_check_needs_a_passphrase()?;
    repair_words_repair_where_a_container_is_read()?;
    mhfe_repair_shows_the_repaired_container()?;
    the_length_question_offers_detection_last()?;
    search_reference_is_recorded_once_read()?;
    a_search_finds_missing_words()
}

/// Zero-12's container phrase with the words at the positions given, from 1, replaced.
pub(super) fn container_with(changes: &[(usize, &str)]) -> Vec<u8> {
    let mut words: Vec<&str> = container().split(' ').collect();
    for &(position, word) in changes {
        if let Some(place) = words.get_mut(position - 1) {
            *place = word;
        }
    }
    words.join(" ").into_bytes()
}

fn line(text: &[u8]) -> Vec<u8> {
    join(&[text, b"\r"])
}

/// A session of `mhfe check --fingerprint --pim 0` at the container prompt.
fn check_at_container() -> Result<Session, Failure> {
    let mut session = Session::check()?;
    session.wait(CONTAINER_ASKED)?;
    Ok(session)
}

/// Zero-12's container phrase with its last word typed as ?, up to the question of what is known
/// for the search without repair words.
pub(super) fn at_the_search(session: &mut Session) -> Result<(), Failure> {
    session.answer(&line(&container_with(&[(24, "?")])), &[CARD_ASKED])?;
    session.answer(b"\r", &[SEARCH_ASKED, b"1 to 5 at once"])
}

/// A reference of the container's own wallet, its decoy fingerprint, up to the question about
/// the container phrase's passphrase.
fn by_the_decoy_fingerprint(session: &mut Session) -> Result<(), Failure> {
    session.answer(b"1", &[REFERENCE_ASKED])?;
    session.answer(
        &line(ZERO_12_DECOY_FINGERPRINT),
        &[CONTAINER_PASSPHRASE_ASKED, LIST_SHOWN],
    )
}

/// `damaged`, with words typed as ?, repaired by zero-12's card, up to the question whether to use
/// the repaired container phrase.
fn repaired_by_the_card(session: &mut Session, damaged: &[u8]) -> Result<(), Failure> {
    session.answer(&line(damaged), &[CARD_HINT, CARD_ASKED])?;
    session.answer(
        &line(ZERO_12_CARD),
        &[REPAIRED_HEADING, REPAIRED_SHOWN, USE_ASKED, LIST_SHOWN],
    )
}

/// Ctrl+C at the password, the summary with the records expected and none of the words.
fn cancelled_at_password(session: &mut Session, label: &str) -> Result<Vec<u8>, Failure> {
    session.answer(CTRL_C, &[b"Cancelled"])?;
    ensure(session.drain_until_exit(10), || {
        format!("{label}: Ctrl+C did not end the tool")
    })?;
    session.ends_with(CANCELLED, &format!("{label}: Ctrl+C"))?;
    Ok(session.summary().to_vec())
}

/// `mhfe check` takes the phrase + passphrase check only with a passphrase (AUD-010): it asks
/// "BIP39 passphrase of the wallet" without "Enter if it has none", refuses an empty one and asks
/// again, and takes BIP39's public test passphrase; on Linux the capped run then stops at the
/// memory reservation, with "Passphrase typed" in the summary.
fn wallet_check_needs_a_passphrase() -> Result<(), Failure> {
    let capped = capped_here();
    let arguments = ["check", "--pim", "0"];
    let mut session = Session::capped(&arguments)?;
    session.wait(b"original seed phrase: ")?;
    session.answer(&line(container().as_bytes()), &[b"Container password: "])?;
    session.answer(&line(SECRET), &[COMPARE_ASKED, LIST_SHOWN])?;
    session.answer(WALLET_CHECK_ENTRY, &[KNOWN_PASSPHRASE_ASKED])?;
    session.answer(b"\r", &[WALLET_CHECK_REFUSED, KNOWN_PASSPHRASE_ASKED])?;
    ensure(!contains(&session.output, b"if it has none"), || {
        "check: Enter offered for no passphrase".to_owned()
    })?;
    if !capped {
        session.ends_with(CANCELLED, "check, wallet check: Ctrl+C")?;
        println!("check: the phrase + passphrase check refuses an empty passphrase and asks again");
        return Ok(());
    }
    session.answer(&line(PUBLIC_PASSPHRASE), &[MEMORY_REFUSED])?;
    ensure(session.drain_until_exit(10), || {
        "check, wallet check: the refusal did not end the tool".to_owned()
    })?;
    session.ends_with(NOT_ENOUGH_RESOURCES, "check, wallet check")?;
    shown_privately("check, wallet check", &session.output, PUBLIC_PASSPHRASE)?;
    ensure(contains(session.summary(), b"Passphrase typed"), || {
        "check, wallet check: the passphrase was not recorded".to_owned()
    })?;
    println!("check: the phrase + passphrase check refuses an empty passphrase, then takes one");
    Ok(())
}

/// The public repair example names both positions, erasures and restored words.
fn check_repair_details(stderr: &[u8], context: &str) -> Result<(), Failure> {
    let text = String::from_utf8_lossy(stderr);
    for (position, restored) in [(3, "tower"), (17, "cycle")] {
        let marker = format!("word {position:>2}");
        let found = text.lines().find(|line| line.contains(&marker));
        ensure(
            found.is_some_and(|line| {
                line.contains("unreadable") && line.contains('→') && line.contains(restored)
            }),
            || format!("{context}: missing erasure and replacement for word {position}: {found:?}"),
        )?;
    }
    Ok(())
}

/// A container phrase with words typed as ? asks for its repair words at once; the repaired
/// container phrase and every repaired word are shown on the private screen, and only "Use it"
/// goes on, to the password, with "Repaired" in the summary and none of the words. Words that are
/// not a container ask whether to type them again or repair them; Enter alone at the repair words
/// goes back to the container phrase. A script gives the card on the line after the container
/// phrase with --repair and is told on standard error what was repaired.
fn repair_words_repair_where_a_container_is_read() -> Result<(), Failure> {
    let damaged = container_with(&[(3, "?"), (17, "?")]);
    let mut session = check_at_container()?;
    repaired_by_the_card(&mut session, &damaged)?;
    session.answer(b"1", &[b"Container password: "])?;
    let summary = cancelled_at_password(&mut session, "repair")?;
    ensure(contains(&summary, b"Container  24 words, valid"), || {
        "repair: no Container record".to_owned()
    })?;
    ensure(contains(&summary, REPAIRED_RECORDED), || {
        "repair: no Repaired record".to_owned()
    })?;
    let third = container().split(' ').nth(2).unwrap_or_default().to_owned();
    for words in [ZERO_12_CARD, third.as_bytes(), USE_ASKED] {
        ensure(!contains(&summary, words), || {
            format!("repair: {} reached the main screen", shown(words))
        })?;
    }
    println!("repair: ? asks for the card, shows the repaired words, uses them on \"Use it\"");

    let typo = container_with(&[(9, "towr")]);
    let mut session = check_at_container()?;
    session.answer(
        &line(&typo),
        &[b"word 9 is not in the", REPAIR_OFFERED, LIST_SHOWN],
    )?;
    session.answer(b"1", &[CONTAINER_ASKED])?;
    session.answer(&line(&typo), &[REPAIR_OFFERED, LIST_SHOWN])?;
    session.answer(b"2", &[CARD_ASKED])?;
    let start = session.output.len();
    session.answer(b"\r", &[CONTAINER_ASKED])?;
    ensure(
        !contains(&session.output[start..], REPAIRED_HEADING),
        || "repair: Enter alone repaired".to_owned(),
    )?;
    session.answer(&line(container().as_bytes()), &[b"Container password: "])?;
    let summary = cancelled_at_password(&mut session, "repair, typo")?;
    ensure(!contains(&summary, b"Repaired"), || {
        "repair, typo: a repair was recorded".to_owned()
    })?;
    println!(
        "repair: a typo offers \"Type it again\" or the card; Enter alone at the card goes back"
    );

    let lines = join(&[&damaged, b"\n", ZERO_12_CARD, b"\n", SECRET, b"\nzz\n\n"]);
    let result = run_plainly(
        &["check", "--stdin", "--repair", "--fingerprint"],
        &lines,
        false,
        capped_here(),
    )?;
    let exit = code(&result);
    ensure(exit == INVALID_INPUT, || {
        format!("repair, script: exit code {exit}")
    })?;
    ensure(contains(&result.stderr, REPAIRED_SHOWN), || {
        format!("repair, script: {}", shown(&result.stderr))
    })?;
    check_repair_details(&result.stderr, "repair, script")?;
    ensure(result.stdout.is_empty(), || {
        "repair, script: wrote to standard output".to_owned()
    })?;
    println!(
        "repair, script: --repair reads the card after the container phrase, says what it repaired"
    );
    Ok(())
}

/// `mhfe repair` repairs a container phrase with its card and shows it after "Use it"; Enter alone
/// at the card searches for a word typed as ?, here by the decoy fingerprint without a password,
/// and the found container phrase is shown the same way. A script gives the container phrase and
/// the card, one per line, and gets the repaired container phrase on standard output.
fn mhfe_repair_shows_the_repaired_container() -> Result<(), Failure> {
    let damaged = container_with(&[(3, "?"), (17, "?")]);
    let mut session = Session::of(&["repair"])?;
    session.wait(CONTAINER_ASKED)?;
    repaired_by_the_card(&mut session, &damaged)?;
    session.answer(b"1", &[REPAIR_RESULT, WRITE_IT_DOWN])?;
    session.answer(b"\r", &[b"Next"])?;
    ensure(session.drain_until_exit(10), || {
        "repair command: it did not end".to_owned()
    })?;
    session.ends_with(0, "repair command")?;
    ensure(contains(session.summary(), REPAIRED_RECORDED), || {
        "repair command: no Repaired record".to_owned()
    })?;
    println!("repair command: the card repairs the container phrase, shown after \"Use it\"");

    let mut session = Session::of(&["repair"])?;
    session.wait(CONTAINER_ASKED)?;
    at_the_search(&mut session)?;
    by_the_decoy_fingerprint(&mut session)?;
    session.answer(b"1", &[FOUND_SHOWN, FOUND_USE_ASKED, LIST_SHOWN])?;
    session.answer(b"1", &[REPAIR_RESULT, WRITE_IT_DOWN])?;
    session.answer(b"\r", &[b"Next"])?;
    ensure(session.drain_until_exit(10), || {
        "repair command, search: it did not end".to_owned()
    })?;
    let (exit, _) = session.close()?;
    ensure(exit == 0, || {
        format!("repair command, search: exit code {exit}")
    })?;
    let summary = session.summary();
    ensure(contains(summary, FOUND_RECORDED), || {
        "repair command, search: no record of the search".to_owned()
    })?;
    ensure(!contains(summary, b"peace"), || {
        "repair command, search: the found word reached the summary".to_owned()
    })?;
    println!("repair command: without the card, the decoy fingerprint finds the missing word");

    let lines = join(&[&damaged, b"\n", ZERO_12_CARD, b"\n"]);
    let result = run_plainly(&["repair", "--stdin"], &lines, false, false)?;
    let exit = code(&result);
    ensure(exit == 0, || {
        format!("repair command, script: exit code {exit}")
    })?;
    ensure(result.stdout.trim_ascii() == container().as_bytes(), || {
        format!("repair, script: {}", shown(&result.stdout))
    })?;
    ensure(contains(&result.stderr, REPAIRED_SHOWN), || {
        format!("repair command, script: {}", shown(&result.stderr))
    })?;
    check_repair_details(&result.stderr, "repair command, script")?;
    println!("repair command, script: the repaired container phrase on standard output");
    Ok(())
}

/// The question about the length offers detection last. In check, under the built-in check, it
/// asks next whether a BIP39 passphrase is used with the original seed phrase, before the work;
/// in rekey it asks how a 24-word phrase is confirmed, as for 24 words.
fn the_length_question_offers_detection_last() -> Result<(), Failure> {
    let capped = capped_here();
    let arguments = ["check", "--pim", "0"];
    let mut session = Session::capped(&arguments)?;
    session.wait(CONTAINER_ASKED)?;
    session.answer(&line(container().as_bytes()), &[b"Container password: "])?;
    session.answer(
        &line(SECRET),
        &[b"The container's built-in check", LIST_SHOWN],
    )?;
    session.answer(b"3", &[LENGTH_ASKED, DETECT_OFFERED, LIST_SHOWN])?;
    session.answer(b"5", &[ORIGINAL_PASSPHRASE_ASKED, LIST_SHOWN])?;
    if capped {
        session.answer(b"1", &[MEMORY_REFUSED])?;
        ensure(session.drain_until_exit(10), || {
            "check, detected: it did not end".to_owned()
        })?;
    } else {
        session.answer(CTRL_C, &[b"Cancelled"])?;
    }
    session.close()?;
    println!("check: the built-in check offers detection, then asks about the passphrase");

    let mut session = Session::of(&["rekey", "--pim", "0", "--mem", "0"])?;
    session.wait(CONTAINER_ASKED)?;
    session.answer(
        &line(container().as_bytes()),
        &[LENGTH_ASKED, DETECT_OFFERED, LIST_SHOWN],
    )?;
    session.answer(b"6", &[b"Old container password"])?;
    session.answer(&line(SECRET), &[CONFIRMATION_ASKED, LIST_SHOWN])?;
    session.answer(CTRL_C, &[b"Cancelled"])?;
    ensure(session.drain_until_exit(10), || {
        "rekey, detected: Ctrl+C did not end the tool".to_owned()
    })?;
    let (exit, _) = session.close()?;
    ensure(exit == CANCELLED, || {
        format!("rekey, detected: exit code {exit}")
    })?;
    println!("rekey: detection asks how a 24-word phrase is confirmed");
    Ok(())
}

/// The one field of a search's reference records nothing on the main screen before the text is
/// read as a fingerprint or an address: a seed phrase typed there is refused as several words, and
/// a word with control characters that is no address is refused and never recorded
/// (AUD-015-SEC001).
fn search_reference_is_recorded_once_read() -> Result<(), Failure> {
    let mut session = check_at_container()?;
    session.answer(&line(&container_with(&[(24, "?")])), &[CARD_ASKED])?;
    session.answer(b"\r", &[SEARCH_ASKED])?;
    session.answer(b"1", &[REFERENCE_ASKED])?;
    session.answer(
        &line(phrase().as_bytes()),
        &[b"without spaces", REFERENCE_ASKED],
    )?;
    session.answer(
        &line(b"bc1\x1b]0;AUD015\x07zz"),
        &[b"checksum or format", REFERENCE_ASKED],
    )?;
    let summary = cancelled_at_password(&mut session, "search reference")?;
    ensure(!contains(&summary, phrase().as_bytes()), || {
        "search reference: the phrase reached the main screen".to_owned()
    })?;
    ensure(!contains(&summary, b"AUD015"), || {
        "search reference: the typed text reached the main screen".to_owned()
    })?;
    ensure(!contains(&summary, b"Reference"), || {
        "search reference: recorded before it was read".to_owned()
    })?;
    println!("search: the reference field records nothing until it is read; a phrase is refused");
    Ok(())
}

/// Two missing words at the container prompt, up to the gap of the container's own wallet's
/// address.
fn two_missing_at_the_gap() -> Result<Session, Failure> {
    let mut session = check_at_container()?;
    session.answer(
        &line(&container_with(&[(5, "?"), (16, "?")])),
        &[CARD_ASKED],
    )?;
    // Two missing words make about 4 million combinations to list first: seconds in a release
    // build, longer in a debug one.
    session.answer_within(
        b"\r",
        &[SEARCH_ASKED, TWO_EXPLAINED, b"1 or 2 at once"],
        120,
    )?;
    session.answer(b"1", &[REFERENCE_ASKED])?;
    session.answer(&line(ZERO_12_DECOY_ADDRESS), &[GAP_ASKED, LIST_SHOWN])?;
    Ok(session)
}

/// Enter alone at the repair words of a container phrase with a word typed as ? asks what is
/// known: zero-12's decoy fingerprint finds its last word without a password, used only after
/// "Use it"; a passphrase the container phrase does not have finds nothing, and the question
/// comes again. Two missing words offer only the container's own wallet: its address, at the gap
/// chosen, finds both; a gap of one's own is typed. "Not now" before a long search asks again; on
/// Linux the capped run then takes the password and stops at the memory reservation.
fn a_search_finds_missing_words() -> Result<(), Failure> {
    let mut session = check_at_container()?;
    at_the_search(&mut session)?;
    by_the_decoy_fingerprint(&mut session)?;
    session.answer(b"2", &[CONTAINER_PASSPHRASE_TYPED])?;
    session.answer(
        &line(PUBLIC_PASSPHRASE),
        &[NOT_IN_CONTAINER_WALLET, SEARCH_ASKED],
    )?;
    by_the_decoy_fingerprint(&mut session)?;
    session.answer(
        b"1",
        &[
            b"Found container phrase, 24 words",
            FOUND_SHOWN,
            FOUND_USE_ASKED,
            LIST_SHOWN,
        ],
    )?;
    session.answer(b"1", &[b"Container password: "])?;
    let summary = cancelled_at_password(&mut session, "search")?;
    ensure(contains(&summary, FOUND_RECORDED), || {
        "search: no record of the search".to_owned()
    })?;
    ensure(!contains(&summary, b"peace"), || {
        "search: the found word reached the main screen".to_owned()
    })?;
    println!("search: the decoy fingerprint finds the missing word; a wrong passphrase asks again");

    // The container's own address, "3…", is read as Bitcoin's and Litecoin's: two coin types.
    let mut session = two_missing_at_the_gap()?;
    session.answer(
        b"1",
        &[
            b"0-1/0-19, 80 addresses",
            CONTAINER_PASSPHRASE_ASKED,
            LIST_SHOWN,
        ],
    )?;
    session.answer_within(b"1", &[TWO_FOUND, FOUND_USE_ASKED], 600)?;
    session.close()?;
    println!("search: two words found by an address of the container's own wallet");

    // A gap of the person's own: a number that is not one is asked again, and the scope stated
    // follows the number taken.
    let mut session = two_missing_at_the_gap()?;
    session.answer(b"4", &[b"Addresses of each chain: "])?;
    session.answer(
        b"0\r",
        &[
            b"Type a whole number of addresses",
            b"Addresses of each chain: ",
        ],
    )?;
    session.answer(
        b"30\r",
        &[b"0-1/0-29, 120 addresses", CONTAINER_PASSPHRASE_ASKED],
    )?;
    session.close()?;
    println!("search: a gap of one's own is typed, refused when it is not a number of addresses");

    let capped = capped_here();
    let arguments = ["check", "--fingerprint", "--pim", "0"];
    let mut session = Session::capped(&arguments)?;
    session.wait(CONTAINER_ASKED)?;
    at_the_search(&mut session)?;
    // "Not now" goes back to the question, not to the container phrase.
    session.answer(
        b"4",
        &[LONG_SEARCH_WARNED, b"Start the search?", LIST_SHOWN],
    )?;
    session.answer(b"2", &[SEARCH_ASKED, b"1 to 5 at once"])?;
    session.answer(
        b"4",
        &[LONG_SEARCH_WARNED, b"Start the search?", LIST_SHOWN],
    )?;
    if capped {
        session.answer(b"1", &[b"Container password: "])?;
        session.answer(&line(SECRET), &[MEMORY_REFUSED])?;
        ensure(session.drain_until_exit(10), || {
            "search, nothing known: the refusal did not end the tool".to_owned()
        })?;
        session.ends_with(NOT_ENOUGH_RESOURCES, "search, nothing known")?;
    } else {
        let (_, settings) = session.close()?;
        ensure(settings == session.original, || {
            "search, nothing known: terminal settings changed".to_owned()
        })?;
    }
    println!("search: nothing known says how long it takes; \"Not now\" asks again");
    Ok(())
}
