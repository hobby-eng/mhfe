//! `mhfe encrypt` up to the password, so without Argon2: its lists, a script, a dumb terminal, a
//! password made by MHFE, real dice, a phrase offered only at a terminal, and the keys that end a
//! command.

use nix::sys::signal::Signal;

use super::password::shown_privately;
use super::session::{
    Session, Start, capped_here, code, contains, find, rfind, run_plainly, shown,
};
use super::{
    BAD_CHECKSUM, CANCELLED, CLEAR, CONTAINER_ASKED, CTRL_C, DOWN, ENTER, ENTER_PRIVATE, ESCAPE,
    IGNORED_KEY, INVALID_INPUT, LEAVE_PRIVATE, LIST_SHOWN, MEMORY_REFUSED, NOT_ENOUGH_RESOURCES,
    NUMBERED_PROMPT, PASSPHRASE_ASKED, PASSPHRASE_RECORD, REPAIR_ASKED, SECRET, UP, WRITE_IT_DOWN,
    container, ensure, join, phrase,
};
use crate::Failure;

/// What the lists of `mhfe encrypt` show: the link of the settings question, the explanation
/// behind ?, and the records of the answers.
const SETTINGS_ASKED: &[u8] = b"#settings-pim-and-memory-level";
const EXPLAINED: &[u8] = b"8-character code";
const OWN_SETTINGS: &[u8] = "PIM 1 · memory level 0".as_bytes();
const PHRASE_RECORDED: &[u8] = b"Phrase     12 words, valid";
const LENGTH_RECORDED: &[u8] = b"Container  24 words (recommended)";
const REPAIR_RECORDED: &[u8] = b"Repair     No repair words";
/// The question before a new password (made_password.rs in the tool), and what a password made
/// asks and records.
const PASSWORD_KIND_ASKED: &[u8] = b"The container password: type your own, or let MHFE make one?";
const TYPED_BACK_ASKED: &[u8] = b"Password as you wrote it down: ";
const NOT_AS_SHOWN: &[u8] = b"That is not the password shown: correct your copy from the screen.";
const MADE_RECORDED: &[u8] =
    b"Password   made by MHFE: 5 words from the EFF list, about 64.6 bits.";
pub(super) fn run() -> Result<(), Failure> {
    encrypt_asks_in_lists_up_to_the_password()?;
    a_script_is_not_asked_about_the_passphrase()?;
    a_dumb_terminal_hides_the_phrase_and_refuses_a_made_password()?;
    a_made_password_is_typed_back()?;
    dice_digits_give_the_words()?;
    a_phrase_is_offered_only_at_a_terminal()?;
    quit_keys_leave_the_private_screen()
}

/// `mhfe encrypt` up to the password: its own settings, PIM 1 after a mistyped one; the phrase,
/// refused once for its checksum and then taken without a question; the length question on a
/// cleared screen, where ? explains both lengths and the arrows and Enter keep 24 words; then at
/// once the question about repair words, nothing about a BIP39 passphrase; no repair words;
/// Ctrl+C at the repeated password ends the tool. The summary records the settings, the phrase's
/// length, the container's and the repair choice, in the order they were asked, and nothing else.
fn encrypt_asks_in_lists_up_to_the_password() -> Result<(), Failure> {
    let mut session = Session::of(&["encrypt"])?;
    // Nothing typed yet: this waits for the whole first question, its link and its list.
    session.answer(b"", &[SETTINGS_ASKED, LIST_SHOWN])?;
    session.answer(b"2", &[b"PIM: "])?;
    session.answer(b"x\r", &[b"whole number", b"PIM: "])?;
    session.answer(b"1\r", &[b"Memory level: "])?;
    session.answer(b"0\r", &[b"seed phrase: "])?;
    // Twelve times the first word fails the checksum; the phrase is asked again.
    session.answer(
        &join(&[BAD_CHECKSUM, b"\r"]),
        &[b"Please type it again", b"seed phrase: "],
    )?;
    // A valid phrase is taken at once, without a question; the next step clears the screen.
    let typed = format!("{}\r", phrase());
    session.answer(typed.as_bytes(), &[CLEAR, b"How long should", LIST_SHOWN])?;
    session.answer(b"?", &[EXPLAINED, LIST_SHOWN])?;
    // Nothing is asked about a passphrase: the length is followed by the repair words.
    session.answer(
        &join(&[IGNORED_KEY, DOWN, UP, ENTER]),
        &[CLEAR, REPAIR_ASKED, LIST_SHOWN],
    )?;
    // No repair words: they would appear only after the encryption.
    session.answer(b"5", &[PASSWORD_KIND_ASKED, LIST_SHOWN])?;
    // The person's own password, the first answer.
    session.answer(b"1", &[b"Container password: "])?;
    session.answer(
        &join(&[SECRET, b"\r"]),
        &[b"Repeat the container password: "],
    )?;
    session.answer(&join(&[SECRET, CTRL_C]), &[b"Cancelled"])?;
    ensure(session.drain_until_exit(10), || {
        "encrypt: Ctrl+C did not end the tool".to_owned()
    })?;
    session.ends_with(CANCELLED, "encrypt: Ctrl+C")?;
    shown_privately("encrypt", &session.output, SECRET)?;
    ensure(!contains(&session.output, IGNORED_KEY), || {
        "encrypt: a key was shown".to_owned()
    })?;
    // The steps stayed on the alternate screen; the main screen got the summary when it ended.
    let summary = session.summary();
    let records = [
        OWN_SETTINGS,
        PHRASE_RECORDED,
        LENGTH_RECORDED,
        REPAIR_RECORDED,
    ];
    let mut places = Vec::new();
    for record in records {
        let place = find(summary, record, 0);
        ensure(place.is_some(), || {
            format!("encrypt: the summary lacks {}", shown(record))
        })?;
        places.push(place.unwrap_or_default());
    }
    ensure(places.is_sorted(), || {
        "encrypt: the summary is not in the order of the questions".to_owned()
    })?;
    for step in [&b"How long should"[..], b"seed phrase: ", EXPLAINED] {
        ensure(!contains(summary, step), || {
            format!("encrypt: {} reached the main screen", shown(step))
        })?;
    }
    ensure(!contains(&session.output, PASSPHRASE_ASKED), || {
        "encrypt: asked about the passphrase".to_owned()
    })?;
    ensure(!contains(summary, PASSPHRASE_RECORD), || {
        "encrypt: a Passphrase record".to_owned()
    })?;
    println!("encrypt: own settings; phrase refused once, then taken at once; ? and the arrows");
    println!("encrypt: nothing asked about a passphrase; the summary has no Passphrase record");
    println!(
        "encrypt: password shown only on the alternate screen; Ctrl+C leaves it, exit code 130"
    );
    println!("encrypt: every step on a cleared screen; only the summary on the main screen");

    let mut session = Session::of(&["encrypt"])?;
    session.answer(b"", &[SETTINGS_ASKED, LIST_SHOWN])?;
    session.answer(ESCAPE, &[b"Cancelled"])?;
    ensure(session.drain_until_exit(10), || {
        "encrypt: Escape did not end the tool".to_owned()
    })?;
    session.ends_with(CANCELLED, "encrypt: Escape")?;
    println!("encrypt: Escape at a list cancels, exit code 130, terminal restored");
    Ok(())
}

/// A script gives the phrase and the password twice, one per line, and is not asked about the
/// wallet's passphrase: the two lines after the phrase are taken as the passwords. They differ,
/// which ends the tool before Argon2. The help lists no passphrase among what encrypt asks for.
fn a_script_is_not_asked_about_the_passphrase() -> Result<(), Failure> {
    let lines = format!("{}\n{}\n{}x\n", phrase(), "synthetic", "synthetic");
    let result = run_plainly(&["encrypt", "--stdin"], lines.as_bytes(), false, false)?;
    let code = code(&result);
    ensure(code == INVALID_INPUT, || {
        format!("encrypt --stdin: exit code {code}")
    })?;
    ensure(
        contains(&result.stderr, b"The password and its repetition differ"),
        || format!("encrypt --stdin: {}", shown(&result.stderr)),
    )?;
    ensure(!contains(&result.stderr, PASSPHRASE_ASKED), || {
        "encrypt --stdin: asked about the passphrase".to_owned()
    })?;
    ensure(!contains(&result.stderr, NUMBERED_PROMPT), || {
        "encrypt --stdin: asked to choose".to_owned()
    })?;
    ensure(result.stdout.is_empty(), || {
        "encrypt --stdin: wrote to standard output".to_owned()
    })?;
    println!(
        "encrypt --stdin: not asked about the passphrase; two different passwords end it, code 2"
    );
    let help = run_plainly(&["encrypt", "--help"], b"", false, false)?.stdout;
    let start = find(&help, b"What it asks for:", 0);
    let end = start.and_then(|start| find(&help, b"Examples:", start));
    let (Some(start), Some(end)) = (start, end) else {
        return Err(Failure(format!(
            "encrypt --help: no section of what it asks for: {}",
            shown(&help)
        )));
    };
    let asks = String::from_utf8_lossy(&help[start..end]).into_owned();
    ensure(
        asks.contains("Original seed phrase") && asks.contains("Password"),
        || format!("encrypt --help: {asks:?}"),
    )?;
    ensure(!asks.to_lowercase().contains("passphrase"), || {
        format!("encrypt --help: asks for a passphrase: {asks:?}")
    })?;
    println!("encrypt --help: no passphrase among what it asks for");
    Ok(())
}

/// A terminal that cannot redraw a list gets no question between the hidden phrase and the
/// hidden password; a password made by MHFE, which needs a private screen, is refused there
/// before anything is asked (AUD-015-SEC003).
fn a_dumb_terminal_hides_the_phrase_and_refuses_a_made_password() -> Result<(), Failure> {
    let arguments = ["encrypt", "--pim", "0"];
    let mut session = Session::start(Start {
        term: "dumb",
        ..Start::of(&arguments)
    })?;
    session.wait(b"Original seed phrase (hidden): ")?;
    let start = session.output.len();
    let typed = format!("{}\r", phrase());
    session.answer(typed.as_bytes(), &[b"Container password (hidden): "])?;
    for asked in [PASSPHRASE_ASKED, NUMBERED_PROMPT] {
        ensure(!contains(&session.output[start..], asked), || {
            format!("encrypt, TERM=dumb: {} before the password", shown(asked))
        })?;
    }
    session.answer(CTRL_C, &[b"Cancelled"])?;
    ensure(session.drain_until_exit(10), || {
        "encrypt, TERM=dumb: Ctrl+C did not end the tool".to_owned()
    })?;
    session.ends_with(CANCELLED, "encrypt, TERM=dumb")?;
    ensure(!contains(&session.output, phrase().as_bytes()), || {
        "encrypt, TERM=dumb: the phrase was shown".to_owned()
    })?;
    println!(
        "encrypt, TERM=dumb: the hidden password right after the hidden phrase, the phrase hidden"
    );
    for command in ["encrypt", "rekey"] {
        let arguments = [command, "--pim", "0", "--new-password", "words"];
        let mut session = Session::start(Start {
            term: "dumb",
            ..Start::of(&arguments)
        })?;
        session.wait(b"shown only on a private screen")?;
        ensure(session.drain_until_exit(10), || {
            format!("{command}, TERM=dumb: the refusal did not end")
        })?;
        session.ends_with(
            INVALID_INPUT,
            &format!("{command} --new-password words, TERM=dumb"),
        )?;
        ensure(!contains(&session.output, b"Original seed phrase"), || {
            format!("{command}: asked first")
        })?;
    }
    println!("encrypt and rekey, TERM=dumb: a made password is refused before anything is asked");
    Ok(())
}

/// The five words of a password made, as shown on their own line.
fn made_words(output: &[u8]) -> Option<Vec<u8>> {
    String::from_utf8_lossy(output)
        .split("\r\n")
        .find_map(|line| {
            let words: Vec<&str> = line.strip_prefix("  ")?.split(' ').collect();
            let plain = words.len() == 5
                && words.iter().all(|word| {
                    !word.is_empty()
                        && word
                            .chars()
                            .all(|char| char.is_ascii_lowercase() || char == '-')
                });
            plain.then(|| words.join(" ").into_bytes())
        })
}

/// `mhfe encrypt` offers a password made by MHFE: five dice words are shown once on a private
/// screen, then typed back from the copy; a wrong copy shows the password again, the right one
/// goes on. The summary records the kind and strength, never the words. On Linux the capped run
/// then stops at the memory reservation, before Argon2; elsewhere Ctrl+C ends it at the
/// reservation's place.
fn a_made_password_is_typed_back() -> Result<(), Failure> {
    let capped = capped_here();
    let arguments = ["encrypt", "--pim", "0"];
    let mut session = Session::capped(&arguments)?;
    session.wait(b"seed phrase: ")?;
    let typed = format!("{}\r", phrase());
    session.answer(typed.as_bytes(), &[b"How long should", LIST_SHOWN])?;
    session.answer(ENTER, &[REPAIR_ASKED, LIST_SHOWN])?;
    session.answer(b"5", &[PASSWORD_KIND_ASKED, LIST_SHOWN])?;
    let start = session.output.len();
    session.answer(b"2", &[b"Write it down now"])?;
    let made = made_words(&session.output[start..]);
    ensure(made.is_some(), || {
        format!(
            "made password: none shown in {}",
            shown(&session.output[start..])
        )
    })?;
    let made = made.unwrap_or_default();
    session.answer(ENTER, &[TYPED_BACK_ASKED])?;
    session.answer(
        &join(&[&made, b"x\r"]),
        &[NOT_AS_SHOWN, b"Write it down now"],
    )?;
    session.answer(ENTER, &[TYPED_BACK_ASKED])?;
    if capped {
        session.answer(&join(&[&made, b"\r"]), &[MEMORY_REFUSED])?;
    } else {
        session.answer(&join(&[&made, b"\r"]), &[b"Encrypting"])?;
        session.answer(CTRL_C, &[b"Cancelled"])?;
    }
    ensure(session.drain_until_exit(10), || {
        "made password: it did not end".to_owned()
    })?;
    session.ends_with(
        if capped {
            NOT_ENOUGH_RESOURCES
        } else {
            CANCELLED
        },
        "made password",
    )?;
    let summary = session.summary();
    ensure(contains(summary, MADE_RECORDED), || {
        "made password: no record of it".to_owned()
    })?;
    ensure(!contains(summary, &made), || {
        "made password: the words reached the main screen".to_owned()
    })?;
    println!(
        "made password: shown once, typed back, a wrong copy shows it again; recorded by kind"
    );
    Ok(())
}

/// Five digits for each word give the word of the list, typed hidden.
fn dice_digits_give_the_words() -> Result<(), Failure> {
    let mut session = Session::of(&["password", "--dice", "--words", "4"])?;
    for number in 1..=4 {
        session.wait(format!("Word {number}: roll five dice").as_bytes())?;
        session.type_keys(b"11111\r")?;
    }
    session.wait(WRITE_IT_DOWN)?;
    ensure(
        contains(&session.output, b"abacus abacus abacus abacus"),
        || "password --dice: no password".to_owned(),
    )?;
    session.type_keys(b"\r")?;
    ensure(session.drain_until_exit(10), || {
        "password --dice: it did not end".to_owned()
    })?;
    session.ends_with(0, "password --dice")?;
    println!("password --dice: the digits give the words of the list");
    Ok(())
}

/// A phrase the person did not ask to export is shown only on a private screen (AUD-007-SEC001):
/// `mhfe rekey` offers to show the phrase for the owner's comparison only when standard output is
/// the terminal, and writes nothing to a pipe.
fn a_phrase_is_offered_only_at_a_terminal() -> Result<(), Failure> {
    for redirected in [false, true] {
        let arguments = ["rekey", "--pim", "0", "--words", "24"];
        let mut start = Start::of(&arguments);
        let mut read_back = None;
        if redirected {
            read_back = Some(start.piped()?);
        }
        let mut session = Session::start(start)?;
        session.wait(CONTAINER_ASKED)?;
        session.answer(
            format!("{}\r", container()).as_bytes(),
            &[b"container password: "],
        )?;
        session.answer(&join(&[SECRET, b"\r"]), &[b"confirmed?", LIST_SHOWN])?;
        let offered = contains(&session.output, b"show me the phrase");
        let (code, _) = session.close()?;
        let label = if redirected {
            "with standard output in a pipe"
        } else {
            "at a terminal"
        };
        ensure(code == CANCELLED, || {
            format!("rekey, {label}: exit code {code}")
        })?;
        ensure(offered != redirected, || {
            format!("rekey, {label}: showing the phrase offered: {offered}")
        })?;
        if let Some(file) = read_back {
            ensure(nothing_written(file), || {
                format!("rekey, {label}: wrote to the pipe")
            })?;
        }
        let state = if redirected { "not offered" } else { "offered" };
        println!("rekey: showing the phrase for comparison {state} {label}");
    }
    Ok(())
}

/// Whether the tool, now ended, wrote nothing to `file`, the other end of its standard output. A
/// pseudo-terminal whose other end is closed reports an error instead of the end of the data.
fn nothing_written(mut file: std::fs::File) -> bool {
    use std::io::Read;
    let mut data = Vec::new();
    let _ = file.read_to_end(&mut data);
    data.is_empty()
}

/// Ctrl+\ and Ctrl+Z at a visible prompt on a private screen, and SIGTERM, end `mhfe repair` as
/// Ctrl+C does: the private screen is left, the terminal restored and the exit code 130
/// (AUD-015-SEC004).
fn quit_keys_leave_the_private_screen() -> Result<(), Failure> {
    for (name, stop) in [
        ("Ctrl+\\", Some(&b"\x1c"[..])),
        ("Ctrl+Z", Some(b"\x1a")),
        ("SIGTERM", None),
    ] {
        let mut session = Session::of(&["repair"])?;
        session.wait(CONTAINER_ASKED)?;
        super::repair::at_the_search(&mut session)?;
        super::repair::at_the_container_wallet(&mut session, None)?;
        match stop {
            Some(key) => session.type_keys(key)?,
            None => session.signal(Signal::SIGTERM)?,
        }
        ensure(session.drain_until_exit(10), || {
            format!("repair, {name}: the tool did not end")
        })?;
        session.ends_with(CANCELLED, &format!("repair, {name}"))?;
        let left = rfind(&session.output, LEAVE_PRIVATE);
        let entered = rfind(&session.output, ENTER_PRIVATE);
        ensure(left > entered, || {
            format!("repair, {name}: the private screen was not left")
        })?;
    }
    println!("repair: Ctrl+\\, Ctrl+Z and SIGTERM leave the private screen and end as Ctrl+C does");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_made_password_is_read_from_its_line() {
        let output = b"Write it down\r\n  abacus brim-full cider dozen easel\r\n";
        assert_eq!(
            made_words(output),
            Some(b"abacus brim-full cider dozen easel".to_vec())
        );
        assert_eq!(made_words(b"\r\n  Two words\r\n"), None);
    }
}
