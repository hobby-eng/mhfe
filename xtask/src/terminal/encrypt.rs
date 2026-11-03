//! `mhfe encrypt` and `mhfe new` up to the password, so without Argon2: their lists, a script, a
//! dumb terminal, a password made by MHFE, real dice, the refusal to show a phrase off a private
//! screen, the wallet check of a new phrase, and the keys that end a command.

use std::process::Stdio;

use nix::pty::openpty;
use nix::sys::signal::Signal;

use super::password::shown_privately;
use super::rekey::has_no_default;
use super::session::{
    Session, Start, capped_here, code, contains, find, rfind, run_plainly, shown,
};
use super::{
    BAD_CHECKSUM, CANCELLED, CLEAR, CONTAINER_ASKED, CTRL_C, DOWN, ENTER, ENTER_PRIVATE, ESCAPE,
    HIGHLIGHT, IGNORED_KEY, INVALID_INPUT, LEAVE_PRIVATE, LIST_SHOWN, MEMORY_REFUSED,
    NOT_ENOUGH_RESOURCES, NUMBERED_PROMPT, PASSPHRASE_ASKED, PASSPHRASE_RECORD, REPAIR_ASKED,
    SECRET, UP, WRITE_IT_DOWN, container, ensure, join, phrase,
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
/// The question of `mhfe new` about a wallet check, its answers, neither marked at the start
/// (AUD-010), the line ? adds below what each answer gives, and the record of the answer.
const CHECK_ASKED: &[u8] = b"Do you want a check that confirms the password at recovery?";
const CHECK_ANSWERS: [&[u8]; 2] = [b"1  No check", b"2  A phrase + passphrase check"];
const CHECK_EXPLAINED: &[u8] = b"A draft, for new wallets only.";
const CHECK_RECORDED: &[u8] = b"  Check ";
/// The hint of that list while no answer is marked, on two lines, and once an arrow has marked
/// one (hint in src/bin/mhfe/choice.rs).
const CHECK_UNMARKED_HINT: &str = "↑ ↓ choose · 1 or 2 at once · ? explains both\r\nEnter selects once one is marked · Esc cancels";
const CHECK_MARKED_HINT: &str =
    "↑ ↓ choose · Enter selects · 1 or 2 at once · ? explains both · Esc cancels";
/// What `mhfe new` says of the wallet check before the draw, and the heading of a new phrase.
const AMPLE: &[u8] = b"The phrase keeps about 240 of its 256 random bits: still far more than";
const NEW_PHRASE_SHOWN: &[u8] = b"New seed phrase, 24 words";
const NEW_PASSPHRASE_ASKED: &[u8] = b"passphrase of the new wallet";

pub(super) fn run() -> Result<(), Failure> {
    encrypt_asks_in_lists_up_to_the_password()?;
    a_script_is_not_asked_about_the_passphrase()?;
    a_dumb_terminal_hides_the_phrase_and_refuses_a_made_password()?;
    a_made_password_is_typed_back()?;
    dice_digits_give_the_words()?;
    a_phrase_is_shown_only_on_a_private_screen()?;
    the_wallet_check_question_has_no_default()?;
    new_draw_shows_its_count()?;
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
    let start = find(&help, b"What it asks for:", 0).unwrap_or(0);
    let end = find(&help, b"Examples:", start).unwrap_or(help.len());
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
/// `mhfe new` and `mhfe wallets` refuse to start, before anything is asked and with nothing on
/// standard output, when standard output goes to a pipe or to a second terminal (AUD-008-SEC004)
/// or TERM is dumb, while `mhfe new` at a terminal goes on; and `mhfe rekey` offers to show the
/// phrase for the owner's comparison only when standard output is the terminal.
fn a_phrase_is_shown_only_on_a_private_screen() -> Result<(), Failure> {
    let refused: &[u8] = b"only on a private screen";
    for command in ["new", "wallets"] {
        let arguments = [command, "--pim", "0"];
        for label in [
            "standard output in a pipe",
            "TERM=dumb",
            "standard output on another terminal",
        ] {
            let mut read_back: Option<std::fs::File> = None;
            let mut start = Start::of(&arguments);
            match label {
                "TERM=dumb" => start.term = "dumb",
                "standard output in a pipe" => read_back = Some(start.piped()?),
                _ => {
                    let other = openpty(None, None)
                        .map_err(|error| Failure(format!("openpty: {error}")))?;
                    read_back = Some(std::fs::File::from(other.master));
                    start.stdout = Some(Stdio::from(other.slave));
                }
            }
            let mut session = Session::start(start)?;
            session.wait(refused)?;
            ensure(session.drain_until_exit(10), || {
                format!("{command}, {label}: the refusal did not end")
            })?;
            session.ends_with(INVALID_INPUT, &format!("{command}, {label}"))?;
            for asked in [&b"assphrase"[..], b"Password", LIST_SHOWN] {
                ensure(!contains(&session.output, asked), || {
                    format!("{command}, {label}: asked {} first", shown(asked))
                })?;
            }
            if let Some(file) = read_back {
                ensure(nothing_written(file), || {
                    format!("{command}, {label}: wrote to it")
                })?;
            }
            println!("{command}: refused with {label}, before any question, exit code 2");
        }
    }
    let mut session = Session::of(&["new", "--pim", "0"])?;
    session.wait(NEW_PASSPHRASE_ASKED)?;
    let (code, _) = session.close()?;
    ensure(code == CANCELLED, || {
        format!("new at a terminal: exit code {code}")
    })?;
    println!("new: at a terminal it goes on to the passphrase");

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

/// `mhfe new` up to the question about the wallet check, after the passphrase typed twice and
/// `typed_ahead` after it.
fn new_at_the_check(typed_ahead: &[u8]) -> Result<Session, Failure> {
    let mut session = Session::of(&["new", "--pim", "0"])?;
    session.wait(NEW_PASSPHRASE_ASKED)?;
    session.answer(&join(&[SECRET, b"\r"]), &[b"Repeat the passphrase"])?;
    session.answer(
        &join(&[SECRET, b"\r", typed_ahead]),
        &[CHECK_ASKED, CHECK_ANSWERS[0], CHECK_ANSWERS[1], LIST_SHOWN],
    )?;
    Ok(session)
}

/// `mhfe new` asks about the wallet check with no answer marked (AUD-010): Enter, also typed
/// ahead with the repeated passphrase, does nothing, ? explains both answers, ↓ marks the first,
/// and Escape cancels before anything is drawn or recorded.
fn the_wallet_check_question_has_no_default() -> Result<(), Failure> {
    // The Enter after the repeated passphrase arrives before the list is drawn.
    let mut session = new_at_the_check(ENTER)?;
    has_no_default(
        "new: the check question",
        &mut session,
        CHECK_ASKED,
        CHECK_UNMARKED_HINT,
    )?;
    session.answer(b"?", &[CHECK_EXPLAINED, LIST_SHOWN])?;
    let explained = rfind(&session.output, CHECK_EXPLAINED).unwrap_or(0);
    ensure(!contains(&session.output[explained..], HIGHLIGHT), || {
        "new: ? marked an answer".to_owned()
    })?;
    session.answer(
        DOWN,
        &[
            &join(&[HIGHLIGHT, b" ", CHECK_ANSWERS[0]]),
            CHECK_MARKED_HINT.as_bytes(),
        ],
    )?;
    session.answer(ESCAPE, &[b"Cancelled"])?;
    ensure(session.drain_until_exit(10), || {
        "new: Escape did not end the tool".to_owned()
    })?;
    session.ends_with(CANCELLED, "new: Escape")?;
    ensure(!contains(&session.output, REPAIR_ASKED), || {
        "new: went on past the check question".to_owned()
    })?;
    shown_privately("new", &session.output, SECRET)?;
    ensure(!contains(session.summary(), CHECK_RECORDED), || {
        "new: an answer to the check question was recorded".to_owned()
    })?;
    println!("new: the check question has no default; Enter, also typed ahead, does nothing");
    println!("new: ? explains both answers, ↓ marks the first; Escape cancels, exit code 130");
    Ok(())
}

/// `mhfe new` with the wallet check draws on one thread, which takes minutes, so it shows its
/// count of draws on one line, and Ctrl+C ends the draw. A phrase found before the first report,
/// about one drawing in 64, ends the drawing first, so it is tried again.
fn new_draw_shows_its_count() -> Result<(), Failure> {
    for _ in 0..5 {
        let mut session = new_at_the_check(b"")?;
        // A list flushes what was typed before it reads keys, so each answer waits for it.
        session.idle(b"", 0.5)?;
        session.answer(b"2", &[AMPLE, REPAIR_ASKED, LIST_SHOWN])?;
        session.idle(b"", 0.5)?;
        session.answer(b"1", &[b"Drawing a phrase that passes the check"])?;
        let seen = session.wait_for(&[b"\r1,024 draws so far", NEW_PHRASE_SHOWN], 60, None)?;
        if seen == NEW_PHRASE_SHOWN {
            session.close()?;
            continue;
        }
        session.wait_for(&[b"\r2,048 draws so far", NEW_PHRASE_SHOWN], 60, None)?;
        session.ends_with(CANCELLED, "new, the draw: Ctrl+C")?;
        println!(
            "new: a draw with the check shows its count on one line; Ctrl+C ends it, exit code 130"
        );
        return Ok(());
    }
    Err(Failure(
        "new: five drawings ended before their first report".to_owned(),
    ))
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
        session.answer(b"1", &[super::repair::REFERENCE_ASKED])?;
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
