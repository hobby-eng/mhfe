//! The password and the container phrase as they are typed: control characters, editing keys,
//! the private screen, Ctrl+C, the check word, the word hints and the passwords after the first
//! of a recovery.

use super::session::{Session, Start, capped_here, contains, count, find, rfind};
use super::text::typed_echo;
use super::{
    BACKSPACE, CANCELLED, CTRL_C, CTRL_U, ENTER, ENTER_PRIVATE, LEAVE_PRIVATE, LIST_SHOWN,
    MEMORY_REFUSED, NOT_ENOUGH_RESOURCES, SECRET, container, ensure, join,
};
use crate::Failure;

/// What the tool prints next after a password: a refused one is asked again ("Please type it
/// again"), an accepted one leads to the fingerprint.
const REFUSED: &[u8] = crate::terminal_texts::REFUSED.as_bytes();
const ACCEPTED: &[u8] = crate::terminal_texts::ACCEPTED.as_bytes();
/// The control characters a terminal in its usual mode acts on instead of passing them on, and
/// others a password may not hold.
const CONTROLS: [(&str, &[u8]); 12] = [
    ("Ctrl+S", b"\x13"),
    ("Ctrl+Q", b"\x11"),
    ("Ctrl+V", b"\x16"),
    ("Ctrl+W", b"\x17"),
    ("Ctrl+R", b"\x12"),
    ("Ctrl+O", b"\x0f"),
    ("Ctrl+\\", b"\x1c"),
    ("Ctrl+Z", b"\x1a"),
    ("TAB", b"\t"),
    ("NUL", b"\x00"),
    ("U+0085", "\u{85}".as_bytes()),
    ("Ctrl+D inside the line", b"\x04"),
];
/// The third public vector of MHFE-PASSWORD-CHECK-1, and the question asked about its check word.
const CHECK_WORD_PASSWORD: &str = "jovial trailing chokehold pavilion cresting ninth";
const CHECK_WORD_ASKED: &[u8] = b"Repair the password with its check word?";
/// The hints below a line of words or a password (typed_line.rs in the tool): how many words
/// begin with one letter, the words that begin with two, and a word that no list has.
const COUNT_HINT: &[u8] = b"136 BIP39 words begin with this letter";
const WORDS_HINT: &[u8] = b"abandon   ability   able";
const NO_WORD_HINT: &[u8] = b"No BIP39 word begins like this.";
const CLEAR_BELOW: &[u8] = b"\x1b[J";
/// The question of `mhfe decrypt` after each password, the note of its first answer with one
/// password and with two, and the record of a password, at the start of its line of the summary.
const ANOTHER_ASKED: &[u8] = b"Recover now, or add another password?";
const ALL_SHOWN_WARNED: &[u8] = b"all their seed phrases are shown on one screen";
const ONE_TYPED: &[u8] = b"with the password typed";
const TWO_TYPED: &[u8] = b"with the 2 passwords typed";
const PASSWORD_RECORDED: &[u8] = b"\n  Password ";
/// The question about the settings of another password and its first answer, the first's, and
/// the question about the BIP39 passphrase of a 24-word container's original seed phrase.
const SETTINGS_ASKED: &[u8] = b"Which settings go with this password?";
const SAME_SETTINGS: &[u8] = b"PIM 0 and memory level 0";
const SOURCE_PASSPHRASE_ASKED: &[u8] = b"Is a BIP39 passphrase used with the original seed phrase?";

pub(super) fn run() -> Result<(), Failure> {
    for (label, key) in CONTROLS {
        a_typed_password_is(label, &join(&[SECRET, key, b"x"]), REFUSED, Some(key))?;
        println!("refused: a password with {label}");
    }
    a_typed_password_is(
        "Unicode",
        &join(&[SECRET, "пароль".as_bytes()]),
        ACCEPTED,
        None,
    )?;
    println!("accepted: a Unicode password");
    // The longest valid password: 4096 bytes typed, 1024 bytes after NFKD. A terminal in line
    // mode would cut it after 4095 bytes on Linux.
    let longest = "\u{1D400}".repeat(1024).into_bytes();
    a_typed_password_is("1024 x U+1D400", &longest, ACCEPTED, None)?;
    println!("accepted: the longest valid password, 4096 bytes before normalization");
    // A TAB would be refused, so the password is accepted only if the key really deleted it.
    a_typed_password_is(
        "Backspace",
        &join(&[SECRET, b"\t", BACKSPACE]),
        ACCEPTED,
        None,
    )?;
    a_typed_password_is("Ctrl+U", &join(&[b"\t", CTRL_U, SECRET]), ACCEPTED, None)?;
    println!("edited: Backspace and Ctrl+U at the password");
    let mut session = Session::check()?;
    session.at_password_prompt()?;
    session.answer(SECRET, &[SECRET])?;
    session.type_keys(CTRL_C)?;
    session.wait(b"Cancelled")?;
    session.ends_with(CANCELLED, "Ctrl+C")?;
    shown_privately("Ctrl+C", &session.output, SECRET)?;
    println!(
        "cancelled: Ctrl+C at the password, exit code 130, private screen left, terminal restored"
    );
    the_check_word_repairs_only_on_choice()?;
    words_are_hinted_as_they_are_typed()?;
    decrypt_takes_more_passwords_off_the_record()
}

/// `mhfe decrypt` at a terminal asks every question before the work. After the first password it
/// asks about the BIP39 passphrase of a 24-word container (AUD-047-SEC002), then whether to
/// recover now or to add another: 2 asks for the settings of another, Enter keeps the first's,
/// then for the password, after which the question counts two, and Enter goes on to the memory
/// reservation. The main screen then records one password, however many were typed
/// (AUD-007-SEC005). On Linux the capped run stops at the memory reservation; elsewhere Ctrl+C
/// ends it at the last question.
fn decrypt_takes_more_passwords_off_the_record() -> Result<(), Failure> {
    let label = "decrypt, two passwords";
    let capped = capped_here();
    let mut session = Session::capped(&["decrypt", "--pim", "0"])?;
    session.at_password_prompt()?;
    session.answer(
        &join(&[SECRET, ENTER]),
        &[SOURCE_PASSPHRASE_ASKED, LIST_SHOWN],
    )?;
    session.answer(
        b"1",
        &[ALL_SHOWN_WARNED, ANOTHER_ASKED, ONE_TYPED, LIST_SHOWN],
    )?;
    session.answer(b"2", &[SETTINGS_ASKED, SAME_SETTINGS, LIST_SHOWN])?;
    session.answer(ENTER, &[b"Container password: "])?;
    session.answer(
        &join(&[SECRET, b"2", ENTER]),
        &[ANOTHER_ASKED, TWO_TYPED, LIST_SHOWN],
    )?;
    ensure(!contains(&session.output, MEMORY_REFUSED), || {
        format!("{label}: memory was reserved before every question")
    })?;
    if capped {
        session.answer(ENTER, &[MEMORY_REFUSED])?;
        ensure(session.drain_until_exit(10), || {
            format!("{label}: the refusal did not end the tool")
        })?;
        session.ends_with(NOT_ENOUGH_RESOURCES, label)?;
    } else {
        session.answer(CTRL_C, &[b"Cancelled"])?;
        ensure(session.drain_until_exit(10), || {
            format!("{label}: Ctrl+C did not end the tool")
        })?;
        session.ends_with(CANCELLED, label)?;
    }
    let summary = session.summary();
    ensure(count(summary, PASSWORD_RECORDED) == 1, || {
        format!("{label}: the summary does not record exactly one password")
    })?;
    ensure(
        !contains(summary, ANOTHER_ASKED)
            && !contains(summary, ALL_SHOWN_WARNED)
            && !contains(summary, TWO_TYPED)
            && !contains(summary, SETTINGS_ASKED),
        || format!("{label}: a question reached the main screen"),
    )?;
    shown_privately(label, &session.output, SECRET)?;
    println!(
        "decrypt: another password and its settings on choice, the passphrase before the work, \
         one password in the summary"
    );
    if capped {
        one_password_without_a_private_screen()?;
        one_password_for_a_stated_short_length()?;
    }
    Ok(())
}

/// `mhfe decrypt --words 12` on a 24-word container takes one password and asks nothing more: its
/// built-in check refuses every other password, and no 24-word reading comes out for the 16-bit
/// check's passphrase (AUD-047-SEC001, AUD-047-ARC002). The capped run stops at the memory
/// reservation.
fn one_password_for_a_stated_short_length() -> Result<(), Failure> {
    let label = "decrypt --words 12";
    let mut session = Session::capped(&["decrypt", "--pim", "0", "--words", "12"])?;
    session.at_password_prompt()?;
    session.answer(&join(&[SECRET, ENTER]), &[MEMORY_REFUSED])?;
    stopped_without(
        &mut session,
        label,
        &[ANOTHER_ASKED, SOURCE_PASSPHRASE_ASKED],
    )?;
    println!("decrypt --words 12: one password, no question about another or the passphrase");
    Ok(())
}

/// A capped run of `mhfe decrypt` stopped at the memory reservation, with exit code 4, having
/// never asked any of `questions`.
fn stopped_without(session: &mut Session, label: &str, questions: &[&[u8]]) -> Result<(), Failure> {
    ensure(session.drain_until_exit(10), || {
        format!("{label}: the refusal did not end the tool")
    })?;
    session.ends_with(NOT_ENOUGH_RESOURCES, label)?;
    match questions
        .iter()
        .find(|question| contains(&session.output, question))
    {
        Some(question) => Err(Failure(format!(
            "{label}: asked {}",
            super::session::shown(question)
        ))),
        None => Ok(()),
    }
}

/// `mhfe decrypt` where no private screen can be opened, as with TERM=dumb, takes one password
/// without the question about another, asks about the passphrase, numbered, and goes on to the
/// memory reservation, where the capped run stops.
fn one_password_without_a_private_screen() -> Result<(), Failure> {
    let label = "decrypt, TERM=dumb";
    let mut session = Session::start(Start {
        term: "dumb",
        capped: true,
        ..Start::of(&["decrypt", "--pim", "0"])
    })?;
    session.wait(b"original seed phrase: ")?;
    session.answer(
        format!("{}\r", container()).as_bytes(),
        &[b"Container password (hidden): "],
    )?;
    session.answer(
        &join(&[SECRET, ENTER]),
        &[SOURCE_PASSPHRASE_ASKED, b"Choice [1]: "],
    )?;
    session.answer(b"1\r", &[MEMORY_REFUSED])?;
    stopped_without(&mut session, label, &[ANOTHER_ASKED])?;
    println!("decrypt, TERM=dumb: one password, no question about another");
    Ok(())
}

/// The secret was shown on the private screen and nowhere after the tool left it.
pub(super) fn shown_privately(label: &str, output: &[u8], secret: &[u8]) -> Result<(), Failure> {
    let at = find(output, secret, 0);
    ensure(at.is_some(), || {
        format!("{label}: the password was never shown")
    })?;
    let at = at.unwrap_or_default();
    let entered = rfind(&output[..at], ENTER_PRIVATE);
    ensure(entered.is_some(), || {
        format!("{label}: the password was shown off the private screen")
    })?;
    let left = find(output, LEAVE_PRIVATE, entered.unwrap_or_default());
    ensure(left.is_some(), || {
        format!("{label}: the private screen was not left")
    })?;
    let after = &output[left.unwrap_or_default()..];
    ensure(find(after, secret, 0).is_none(), || {
        format!("{label}: the password reached the main screen")
    })
}

/// A password typed at `mhfe check`'s prompt is refused or accepted as `expected`; `not_shown`,
/// a key, is never written back; the terminal is restored.
fn a_typed_password_is(
    label: &str,
    password: &[u8],
    expected: &[u8],
    not_shown: Option<&[u8]>,
) -> Result<(), Failure> {
    let mut session = Session::check()?;
    session.at_password_prompt()?;
    let prompt = session.output.len();
    session.type_keys(&join(&[password, b"\r"]))?;
    let seen = session.wait_for(&[REFUSED, ACCEPTED], 10, None)?;
    ensure(seen == expected, || {
        format!(
            "{label}: expected {:?}, the tool answered {:?}",
            super::session::shown(expected),
            super::session::shown(seen)
        )
    })?;
    if let Some(key) = not_shown {
        ensure(find(&session.output[prompt..], key, 0).is_none(), || {
            format!("{label}: the key was written back")
        })?;
    }
    let (_, settings) = session.close()?;
    if password.starts_with(SECRET) {
        shown_privately(label, &session.output, SECRET)?;
    }
    ensure(settings == session.original, || {
        format!("{label}: the terminal settings were not restored")
    })
}

/// A password with a check word (MHFE-PASSWORD-CHECK-1) is repaired only on the person's choice
/// and before Argon2: a word typed as ? is restored as the third public vector says, also after a
/// stray leading space, which the repair removes; a wrong word gets the question with the password
/// as typed first, and "Type the password again" asks for it again. The summary records how the
/// check word came out and none of the words.
fn the_check_word_repairs_only_on_choice() -> Result<(), Failure> {
    let missing = CHECK_WORD_PASSWORD.replace("chokehold", "?");
    let mut session = Session::check()?;
    session.at_password_prompt()?;
    let typed = format!("{missing}\r");
    session.answer(
        typed.as_bytes(),
        &[CHECK_WORD_ASKED, b"Word 3: chokehold", LIST_SHOWN],
    )?;
    session.answer(ENTER, &[ACCEPTED])?;
    session.ends_with(CANCELLED, "check word")?;
    expect_record(
        &session,
        b"Password   typed, word 3 repaired by its check word",
        b"chokehold",
    )?;
    println!("check word: a word typed as ? restored on Enter, recorded without the words");

    let mut session = Session::check()?;
    session.at_password_prompt()?;
    let wrong = format!("{}\r", CHECK_WORD_PASSWORD.replace("ninth", "zoom"));
    session.answer(
        wrong.as_bytes(),
        &[
            CHECK_WORD_ASKED,
            b"Word 6: ninth instead of zoom",
            LIST_SHOWN,
        ],
    )?;
    session.answer(b"2", &[b"Container password: "])?;
    let right = format!("{CHECK_WORD_PASSWORD}\r");
    session.answer(right.as_bytes(), &[ACCEPTED])?;
    session.ends_with(CANCELLED, "check word")?;
    expect_record(&session, b"Password   typed, its check word fits", b"ninth")?;
    println!("check word: a wrong word asked about, typed again, then the fit recorded");

    let mut session = Session::check()?;
    session.at_password_prompt()?;
    // The stray space of a password typed in a hurry: the repair also removes it.
    let typed = format!(" {missing}\r");
    session.answer(
        typed.as_bytes(),
        &[
            CHECK_WORD_ASKED,
            b"Word 3: chokehold",
            b"extra spaces removed",
            LIST_SHOWN,
        ],
    )?;
    session.answer(ENTER, &[ACCEPTED])?;
    session.ends_with(CANCELLED, "check word")?;
    let record = b"Password   typed, word 3 repaired by its check word; extra spaces removed";
    expect_record(&session, record, b"chokehold")?;
    println!("check word: a leading space removed together with the repair");
    Ok(())
}

/// The summary holds `record` and not `word`.
fn expect_record(session: &Session, record: &[u8], word: &[u8]) -> Result<(), Failure> {
    let summary = session.summary();
    ensure(find(summary, record, 0).is_some(), || {
        format!("check word: no record {}", super::session::shown(record))
    })?;
    ensure(find(summary, word, 0).is_none(), || {
        "check word: a word reached the main screen".to_owned()
    })
}

/// Below the container phrase, the words of the BIP39 list are hinted as they are typed: one
/// letter gives how many begin with it, two the words. Tab completes a word, Ctrl+W deletes the
/// last one, and a word no list has is said. The container typed with four letters of each word
/// and Tab is the container. At the password, words of the EFF list are hinted, and Tab stays a
/// character of the password. No hint is left on the main screen.
fn words_are_hinted_as_they_are_typed() -> Result<(), Failure> {
    let mut session = Session::check()?;
    session.wait(b"original seed phrase: ")?;
    session.answer(b"a", &[COUNT_HINT])?;
    session.answer(b"b", &[WORDS_HINT])?;
    session.answer(b"ou\t", &[b"about "])?;
    session.answer(b"xq", &[NO_WORD_HINT])?;
    session.answer(b"\x17\x17", &[CLEAR_BELOW])?;
    let start = session.output.len();
    // Four letters of each longer word, then Tab: the whole word and a space. A shorter word may
    // begin a longer one, as "rib" begins "ribbon", so it is typed whole with its space.
    let mut shortened: Vec<u8> = container()
        .split(' ')
        .flat_map(|word| {
            match word.get(..4) {
                Some(start) if word.len() >= 4 => format!("{start}\t"),
                _ => format!("{word} "),
            }
            .into_bytes()
        })
        .collect();
    shortened.push(b'\r');
    session.answer(&shortened, &[b"Container password: "])?;
    let typed = format!("{} ", container());
    ensure(
        find(&typed_echo(&session.output[start..]), typed.as_bytes(), 0).is_some(),
        || "hints: Tab did not complete the container".to_owned(),
    )?;
    session.answer(b"jov", &[b"jovial"])?;
    session.answer(b"\t", &[CLEAR_BELOW])?;
    let (_, settings) = session.close()?;
    ensure(settings == session.original, || {
        "hints: the terminal settings were not restored".to_owned()
    })?;
    let summary = session.summary();
    for hint in [COUNT_HINT, b"jovial", NO_WORD_HINT] {
        ensure(find(summary, hint, 0).is_none(), || {
            format!(
                "hints: {} reached the main screen",
                super::session::shown(hint)
            )
        })?;
    }
    println!("hints: a count after one letter, the words after two, a word no list has said");
    println!("hints: Tab completes the container from four letters a word; Ctrl+W deletes a word");
    println!("hints: EFF words below the password, where Tab stays part of the password");
    Ok(())
}
