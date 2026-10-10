//! `mhfe repair` and `mhfe repair-words`: repair words for a container phrase (mhfe::repair, the
//! optional profile MHFE-REPAIR-1 of the specification). A few extra words, kept on a card apart
//! from the container phrase, repair it when words rust away, are scratched or were copied wrongly,
//! without the password and without Argon2.

use anstream::{eprintln, println};
use clap::Args;
use mhfe::memory::LockedText;
use mhfe::repair::{self, ContainerReading, Repaired};
use mhfe::search::DECOY_SCAN_GAP;
use mhfe::wallet::SearchLimits;
use mhfe::word_hints::WordList;
use mhfe::{ContainerFacts, Password, WorkFactor};

use crate::choice::{self, Answer, Question};
use crate::container_search;
use crate::exit::{refused, Failure, SUCCESS};
use crate::flow::Flow;
use crate::readme;
use crate::settings::{self, Operation, Settings};
use crate::style::{self, paint, ACCENT, HEADING, MUTED, STRONG};
use crate::terminal::{self, Input, PrivateScreen, Wallet};

#[derive(Args)]
pub struct RepairOptions {
    /// The settings of the container, for a search without its repair words
    #[command(flatten)]
    settings: Settings,

    #[command(flatten)]
    scan_gap: ScanGapOption,

    /// Read the answers from standard input (for scripts)
    #[arg(long, long_help = repair_stdin_help())]
    stdin: bool,
}

#[derive(Args)]
pub struct WordsOptions {
    /// Number of repair words: 2, 4, 6 or 8
    #[arg(long, value_name = "N", long_help = count_help())]
    count: Option<usize>,

    /// Read the container from standard input (for scripts)
    #[arg(long, requires = "count", long_help = words_stdin_help())]
    stdin: bool,
}

fn repair_stdin_help() -> String {
    style::option_help(&[
        "Read the answers from standard input (for scripts).",
        "Input: the container phrase, then the repair words, one line each, with ? for a word \
         that cannot be read. Output: the repaired container on one line, or nothing when there \
         is nothing to repair.",
    ])
}

fn count_help() -> String {
    style::option_help(&[
        &format!("Number of repair words: {}.", count_list()),
        "Asked at a terminal when not given; a script must give it.",
    ])
}

/// The numbers of repair words a card has, as text: "2, 4, 6 or 8".
fn count_list() -> String {
    let counts: Vec<String> = repair::REPAIR_WORD_COUNTS
        .iter()
        .map(ToString::to_string)
        .collect();
    style::or_list(&counts)
}

fn words_stdin_help() -> String {
    style::option_help(&[
        "Read the container from standard input (for scripts); needs --count.",
        "Input: the container on one line. Output: the repair words on one line.",
    ])
}

/// The end of `mhfe repair -h` and `--help`.
pub fn repair_help() -> String {
    style::help_section(
        "Examples:",
        &[
            (
                "mhfe repair",
                "Type the container phrase and the card; ? for a word that cannot be read",
            ),
            (
                "mhfe repair --pim 1",
                "The same; a search without the card recovers with PIM 1",
            ),
            (
                "your-program | mhfe repair --stdin",
                "A script: the container phrase and the card from another program, the \
                 repaired container out",
            ),
        ],
    )
}

/// The end of `mhfe repair-words -h` and `--help`.
pub fn words_help() -> String {
    style::help_section(
        "Examples:",
        &[
            ("mhfe repair-words", "Choose how many repair words to make"),
            (
                "mhfe repair-words --count 4",
                "Four repair words, the recommended number",
            ),
            (
                "your-program | mhfe repair-words --stdin --count 4",
                "A script: the container from another program, the four words out",
            ),
        ],
    )
}

/// The top of `mhfe repair --help`.
pub fn repair_about() -> String {
    style::command_about(&[
        "Repair a container phrase with its repair words",
        "Repairs the words of a container phrase that cannot be read or were copied wrongly, from \
         the repair words kept on a card, without the password. Type ? for a word that cannot be \
         read. Each repair word repairs one unreadable word; two repair one wrong word.",
        "Without the card, Enter alone at a terminal searches for up to two words typed as ?, \
         as decrypt does: by the container's own wallet, without the password, or with the \
         password by your wallet or the original seed phrase's own checks. --pim, --mem and \
         --scan-gap are for that search; the settings are asked when not given.",
    ])
}

/// The top of `mhfe repair-words --help`.
pub fn words_about() -> String {
    style::command_about(&[
        "Make repair words for a container phrase",
        &format!(
            "Makes {} repair words for a container, to keep on a card apart from the container \
             phrase. mhfe repair then repairs the container phrase with them, without the \
             password.",
            count_list()
        ),
    ])
}

/// `--repair` of the commands that read a container phrase: decrypt, check, rekey and wallets.
#[derive(Args)]
pub struct RepairOption {
    /// Repair the container phrase with its repair words
    #[arg(long, long_help = repair_option_help())]
    repair: bool,

    #[command(flatten)]
    scan_gap: ScanGapOption,
}

impl RepairOption {
    /// When the repair words are asked for, by a command that reads a container made at `work`
    /// for `operation`, which a search for missing words needs.
    pub fn card(&self, operation: Operation, work: WorkFactor) -> CardAsked {
        let search = SearchContext {
            operation,
            work: SearchWork::Chosen(work),
            scan_gap: self.scan_gap.gap,
        };
        if self.repair {
            CardAsked::Always(search)
        } else {
            CardAsked::WhenNeeded(search)
        }
    }
}

/// `--scan-gap` of the commands that may search for two missing container words, declared once
/// (AUD-017-ARC003).
#[derive(Args)]
pub struct ScanGapOption {
    #[arg(
        long = "scan-gap",
        value_name = "N",
        value_parser = scan_gap_parser(),
        help = format!("Scan gap for two missing words (default {DECOY_SCAN_GAP})"),
        long_help = scan_gap_help()
    )]
    gap: Option<u32>,
}

/// `--scan-gap`: 1 to [`SearchLimits::MOST`] addresses of each chain, as the browser package and
/// the library take it.
fn scan_gap_parser() -> clap::builder::RangedI64ValueParser<u32> {
    clap::value_parser!(u32).range(1..=i64::from(SearchLimits::MOST))
}

/// The help of `--scan-gap`, its default from the library's [`DECOY_SCAN_GAP`].
fn scan_gap_help() -> String {
    style::option_help(&[
        &format!(
            "Addresses of each chain a search for two missing words covers (default \
             {DECOY_SCAN_GAP})."
        ),
        &format!(
            "Without the repair words, two words of the container phrase are found by an address \
             of the container's own wallet among the first N receiving and N change addresses of \
             its first account. {DECOY_SCAN_GAP} is the gap of unused addresses a wallet leaves; \
             give more for an address further on: the search takes longer in proportion. Asked \
             at a terminal when not given."
        ),
    ])
}

fn repair_option_help() -> String {
    style::option_help(&[
        "Repair the container phrase with its repair words.",
        "The repair words are asked right after the container phrase; a script gives them on \
         the next line. Without it, a terminal asks for them when a word is typed as ? or when \
         the words are not a valid container.",
    ])
}

/// What a search for missing words needs from the command: the password it asks for and the
/// settings of the container.
#[derive(Clone, Copy)]
pub struct SearchContext {
    pub operation: Operation,
    pub work: SearchWork,
    /// `--scan-gap`, or `None` to ask.
    pub scan_gap: Option<u32>,
}

/// The settings a search that recovers candidates runs at.
#[derive(Clone, Copy)]
pub enum SearchWork {
    /// Those the command settled before the container phrase, as a recovery needs them anyway.
    Chosen(WorkFactor),
    /// Settled once such a search is chosen, for `mhfe repair`, which recovers nothing else.
    Ask(Settings),
}

impl SearchContext {
    /// The settings of a search that recovers candidates, asked for here where the command has
    /// not settled them.
    pub fn work(&self, input: &mut Input) -> Result<WorkFactor, Failure> {
        match self.work {
            SearchWork::Chosen(work) => Ok(work),
            SearchWork::Ask(given) => settings::choose(given, input, self.operation),
        }
    }
}

/// When the repair words of a container phrase are asked for where the container is read.
#[derive(Clone, Copy)]
pub enum CardAsked {
    /// Right after the container phrase, as `--repair` asks.
    Always(SearchContext),
    /// At a terminal, when a word is typed as `?` or the words are not a container.
    WhenNeeded(SearchContext),
    /// Never, where repair words are made rather than used.
    Never,
}

/// A container phrase as typed, repaired with its card, found by a search or as it was, ready
/// to be read.
pub struct Reviewed {
    pub words: LockedText,
    /// What was repaired, for the summary, without the words: "word 3 of the container phrase".
    pub repaired: Option<String>,
    /// The container password, when a search asked for it already.
    pub password: Option<Password>,
    /// What a search for missing words matched, such as "the container's own wallet: master key
    /// fingerprint e0f73b78", for a check to list among its matches.
    pub found_by: Option<String>,
}

impl Reviewed {
    fn as_typed(words: LockedText) -> Self {
        Self {
            words,
            repaired: None,
            password: None,
            found_by: None,
        }
    }
}

/// Looks at a container phrase as typed before it is read and repairs it with its card where
/// `asked` says so (`ContainerReading` decides). `None` asks for the container phrase again.
pub fn review(
    input: &mut Input,
    written: LockedText,
    asked: CardAsked,
) -> Result<Option<Reviewed>, Failure> {
    let reading = ContainerReading::read(&written);
    match asked {
        // A length no container has is refused where it is read, with its usual message.
        CardAsked::Never => Ok(Some(Reviewed::as_typed(written))),
        CardAsked::Always(_) if matches!(reading, ContainerReading::WrongLength(_)) => {
            Ok(Some(Reviewed::as_typed(written)))
        }
        CardAsked::Always(search) => repair_with_card(input, &written, &reading, search),
        // A script gives its lines in a fixed order: only --repair adds the card's line.
        CardAsked::WhenNeeded(_) if input.is_script() || !reading.can_be_repaired() => {
            Ok(Some(Reviewed::as_typed(written)))
        }
        CardAsked::WhenNeeded(search) => {
            if let ContainerReading::NotAContainer = reading {
                // A typing mistake, most often: said as reading it would say it, then asked.
                if let Err(error) = ContainerFacts::read(&written) {
                    style::retry(refused(&error, ""));
                }
                if !wants_repair(input)? {
                    return Ok(None);
                }
            }
            repair_with_card(input, &written, &reading, search)
        }
    }
}

/// Asks, under words that are not a container, whether to type them again or repair them.
fn wants_repair(input: &mut Input) -> Result<bool, Failure> {
    let answers = [
        Answer::new("Type it again", "after a typing mistake"),
        Answer::new(
            "Repair it with its repair words",
            "from the card kept apart from it",
        ),
    ];
    let question = Question {
        text: "Type the container phrase again, or repair it?",
        explanation: &[],
        more: Some(readme::REPAIR),
        record: None,
    };
    Ok(input.choose_here(&question, &answers)? == 1)
}

/// Said where a container phrase is typed that its repair words, or a search, can repair.
pub const UNREADABLE_HINT: &str =
    "Type ? for a word you cannot read; four letters of a word are enough.";

/// What the person is told where the repair words are asked for.
const CARD_HINT: &str =
    "Type the repair words as written on the card; ? for a word you cannot read.";
/// What Enter alone does there: for missing words, a search; otherwise the container again.
const NO_CARD_SEARCH_HINT: &str = "Enter alone if you have no repair words, lost or forgot them.";
const NO_CARD_BACK_HINT: &str = "Enter alone types the container phrase again.";

/// Asks for the repair words of `written` and repairs it. At a terminal every repaired word is
/// shown and the person decides whether to use the repaired container phrase. Enter alone at the
/// card searches for words marked missing (`container_search`), or goes back to the container
/// phrase for words that are not a container. A script uses the repair and is told what it
/// repaired on standard error, its output staying the command's result alone.
fn repair_with_card(
    input: &mut Input,
    written: &str,
    reading: &ContainerReading,
    search: SearchContext,
) -> Result<Option<Reviewed>, Failure> {
    let marked = matches!(reading, ContainerReading::Marked { .. });
    if !input.is_script() {
        eprintln!();
        style::hint(CARD_HINT);
        style::hint(if marked {
            NO_CARD_SEARCH_HINT
        } else {
            NO_CARD_BACK_HINT
        });
    }
    let repaired = loop {
        let card = input.visible_words("Repair words: ", WordList::Bip39)?;
        if card.trim().is_empty() && input.can_ask_again() {
            return if marked {
                container_search::search_missing(input, written, search)
            } else {
                Ok(None)
            };
        }
        let then = "Type them again, or Enter alone without them.";
        if let Some(repaired) = input.accepted(repair::repair(written, &card), then)? {
            break repaired;
        }
    };
    if repaired.changes.is_empty() {
        style::ok(NOTHING_TO_REPAIR);
        return Ok(Some(Reviewed::as_typed(LockedText::copy_of(
            &repaired.container,
        ))));
    }
    if input.is_script() {
        // A script is told every repaired word too, before the repaired container phrase is used,
        // so that the written phrase can be corrected.
        report_changes(&repaired);
    } else {
        show_repaired(&repaired);
        if !uses_repair(input)? {
            return Ok(None);
        }
    }
    Ok(Some(Reviewed {
        words: LockedText::copy_of(&repaired.container),
        repaired: Some(format!(
            "{}, with its repair words",
            repaired_parts(&repaired)
        )),
        password: None,
        found_by: None,
    }))
}

/// Said when the card finds nothing to repair.
const NOTHING_TO_REPAIR: &str =
    "The container phrase and its repair words agree: nothing to repair.";

/// The repaired container phrase and every repaired word, below the words as typed. To standard
/// error, as everything a read container shows: the command's output stays its result alone.
fn show_repaired(repaired: &Repaired) {
    eprintln!();
    eprintln!(
        "{}",
        paint(
            HEADING,
            format!(
                "Repaired container phrase, {} words",
                repaired.container.split(' ').count()
            )
        )
    );
    for line in style::boxed_words(&repaired.container) {
        eprintln!("{}", *line);
    }
    report_changes(repaired);
}

/// The answers whether to use the repaired container phrase.
fn use_answers() -> [Answer; 2] {
    [
        Answer::new("Use it", "and correct your written phrase"),
        Answer::new("Type the container phrase again", "the repair is not used"),
    ]
}

/// Asks whether to go on with the repaired container phrase.
fn uses_repair(input: &mut Input) -> Result<bool, Failure> {
    let answers = use_answers();
    let question = Question {
        text: "Use the repaired container phrase?",
        explanation: &[],
        more: None,
        record: None,
    };
    Ok(input.choose_here(&question, &answers)? == 0)
}

/// The title of `mhfe repair`, as its settings name the operation.
const REPAIR_TITLE: &str = Operation::Repair.title();
/// The title of `mhfe repair-words`, which the menu offers beside it.
pub const WORDS_TITLE: &str = "Make repair words";

pub fn run_repair(options: RepairOptions) -> Result<i32, Failure> {
    let mut input = Input::new(options.stdin);
    // At a terminal every step on a screen of its own, the summary at the end.
    let flow = Flow::start(&input, REPAIR_TITLE);
    style::title(REPAIR_TITLE);
    // Read and repaired as every command reads a container phrase: its repair words right after
    // it, and without them, a search for words typed as ? (container_search), whose settings are
    // asked only once a search that recovers candidates is chosen.
    let search = SearchContext {
        operation: Operation::Repair,
        work: SearchWork::Ask(options.settings),
        scan_gap: options.scan_gap.gap,
    };
    let read = terminal::read_container(&mut input, REPAIR_TITLE, CardAsked::Always(search))?;
    if read.repaired.is_none() {
        // The card agreed with the container phrase, which the repair has said already.
        flow.finish();
        return Ok(SUCCESS);
    }
    let container = read.facts.words();
    // The repaired container is shown privately, as a container always is.
    let screen = PrivateScreen::enter_to_show(&input);
    if screen.is_active() {
        style::title(REPAIR_TITLE);
    }
    eprintln!();
    eprintln!(
        "{}",
        paint(
            HEADING,
            format!("Repaired container, {} words", container.split(' ').count())
        )
    );
    terminal::print_phrase(container, Wallet::Container, &input);
    if screen.is_active() {
        terminal::wait_to_leave()?;
    }
    drop(screen);
    flow.finish();
    style::fact_wrapped(
        "Next",
        &format!(
            "correct your written container phrase; rehearse with {}",
            paint(ACCENT, "mhfe check")
        ),
    );
    style::more(readme::REPAIR);
    Ok(SUCCESS)
}

pub fn run_words(options: WordsOptions) -> Result<i32, Failure> {
    if let Some(count) = options.count {
        repair::require_count(count)?;
    }
    let mut input = Input::new(options.stdin);
    let flow = Flow::start(&input, WORDS_TITLE);
    style::title(WORDS_TITLE);
    let read = terminal::read_container(&mut input, WORDS_TITLE, CardAsked::Never)?;
    let container = read.facts;
    let count = match options.count {
        Some(count) => count,
        // Without --count a script is refused by clap, so the person at a terminal is asked.
        None => ask_count(&mut input, false)?.unwrap_or(repair::RECOMMENDED_REPAIR_WORDS),
    };
    let words = repair::repair_words(container.words(), count)?;
    let screen = PrivateScreen::enter_to_show(&input);
    if screen.is_active() {
        style::title(WORDS_TITLE);
    }
    print_card(&words, &input);
    if screen.is_active() {
        terminal::wait_to_leave()?;
    }
    drop(screen);
    flow.finish();
    style::fact_wrapped(
        "Keep",
        "the repair words on a card, apart from the container phrase",
    );
    style::more(readme::REPAIR);
    Ok(SUCCESS)
}

/// Asks how many repair words a container phrase gets, the recommended four first; with
/// `offer_none`, as when a container is made, "none" too, which gives `None`.
pub fn ask_count(input: &mut Input, offer_none: bool) -> Result<Option<usize>, Failure> {
    // The recommended count first, then the others in order, each with what it repairs.
    let counts: Vec<usize> = std::iter::once(repair::RECOMMENDED_REPAIR_WORDS)
        .chain(
            repair::REPAIR_WORD_COUNTS
                .into_iter()
                .filter(|&count| count != repair::RECOMMENDED_REPAIR_WORDS),
        )
        .collect();
    let mut answers: Vec<Answer> = counts
        .iter()
        .map(|&count| {
            let (unreadable, wrong) = repair::capacity(count);
            let recommended = if count == repair::RECOMMENDED_REPAIR_WORDS {
                " (recommended)"
            } else {
                ""
            };
            let words = if wrong == 1 { "word" } else { "words" };
            Answer::new(
                format!("{count} repair words{recommended}"),
                format!("{unreadable} unreadable or {wrong} wrong {words}"),
            )
        })
        .collect();
    if offer_none {
        answers.push(Answer::new("No repair words", "nothing to keep apart"));
    }
    let question = Question {
        text: "Repair words for the container phrase?",
        explanation: REPAIR_EXPLAINED,
        more: Some(readme::REPAIR),
        record: Some("Repair"),
    };
    let chosen = input.choose(&question, &answers)?;
    Ok(counts.get(chosen).copied())
}

/// What repair words do, under the question whether to make them.
const REPAIR_EXPLAINED: &[&str] =
    &["They fix unreadable or miscopied container words without the password."];

/// `--repair-words` of the commands that make a container: encrypt, new and rekey. The answer to
/// the question whether a new container gets repair words, as an option (the owner's rule that
/// every answer that is not a secret is an option too).
#[derive(Args)]
pub struct RepairWordsOption {
    #[arg(
        long = "repair-words",
        value_name = "N",
        help = format!("Repair words: {}, or 0 for none", count_list()),
        long_help = repair_words_help()
    )]
    count: Option<usize>,
}

impl RepairWordsOption {
    /// Refuses at the start, before anything secret is asked or computed, a count no card has.
    pub fn check(&self) -> Result<(), Failure> {
        match self.count {
            None | Some(NO_REPAIR_WORDS) => Ok(()),
            Some(count) => Ok(repair::require_count(count)?),
        }
    }

    /// The repair words of the new container: the count given, none for 0, and otherwise the
    /// question at a terminal; a script that gives none gets none.
    pub fn choose(&self, input: &mut Input) -> Result<Option<usize>, Failure> {
        match self.count {
            Some(NO_REPAIR_WORDS) => Ok(None),
            Some(count) => Ok(Some(count)),
            None => ask_when_creating(input),
        }
    }
}

/// `--repair-words 0`: no repair words.
const NO_REPAIR_WORDS: usize = 0;

fn repair_words_help() -> String {
    style::option_help(&[
        &format!(
            "Repair words of the new container: {}, or {NO_REPAIR_WORDS} for none.",
            count_list()
        ),
        "Asked at a terminal when not given; a script that does not give it gets none.",
    ])
}

/// At a terminal, asks whether a new container gets repair words; a script, whose answers come in
/// a documented order, gets none.
fn ask_when_creating(input: &mut Input) -> Result<Option<usize>, Failure> {
    if input.is_script() || !choice::can_run() {
        return Ok(None);
    }
    ask_count(input, true)
}

/// The repair card as it is written down: the profile's name, then the words numbered as "1/4",
/// as the specification advises, so that the card tells how many words it has. A script gets the
/// bare words.
pub fn print_card(words: &str, input: &Input) {
    if input.is_script() {
        println!("{words}");
        return;
    }
    let count = words.split(' ').count();
    eprintln!();
    eprintln!(
        "{} {}",
        paint(HEADING, "Repair card"),
        paint(STRONG, repair::PROFILE)
    );
    for row in words
        .split(' ')
        .enumerate()
        .collect::<Vec<_>>()
        .chunks(CARD_WORDS_PER_ROW)
    {
        let cells: Vec<String> = row
            .iter()
            .map(|(index, word)| {
                format!(
                    "{} {}",
                    paint(MUTED, format!("{:>3}/{count}", index + 1)),
                    paint(STRONG, format!("{word:<8}"))
                )
            })
            .collect();
        println!(" {}", cells.join("  "));
    }
    style::hint("Write it on a card as shown, and keep the card apart from the container phrase.");
}

/// Repair words a row of the card, as the words of a phrase are shown.
const CARD_WORDS_PER_ROW: usize = 4;

/// What was repaired: the summary, then a line for each word with what was read and what it
/// became, as a terminal and a script show it.
fn report_changes(repaired: &Repaired) {
    style::ok(what_was_repaired(repaired));
    for change in &repaired.changes {
        let place = if change.on_card { "card" } else { "word" };
        let read = change.read.as_deref().unwrap_or("unreadable");
        eprintln!(
            "  {} {} → {}",
            paint(MUTED, format!("{place} {:>2}", change.position)),
            paint(MUTED, format!("{read:<10}")),
            paint(STRONG, &change.word)
        );
    }
}

/// "Repaired words 3 and 17 of the container phrase and word 2 of the card."
fn what_was_repaired(repaired: &Repaired) -> String {
    format!("Repaired {}.", repaired_parts(repaired))
}

/// "words 3 and 17 of the container phrase and word 2 of the card"
fn repaired_parts(repaired: &Repaired) -> String {
    let list = |positions: &[usize]| -> String {
        let numbers: Vec<String> = positions.iter().map(ToString::to_string).collect();
        style::and_list(&numbers)
    };
    let part = |positions: &[usize], of: &str| -> Option<String> {
        match positions.len() {
            0 => None,
            1 => Some(format!("word {} of the {of}", list(positions))),
            _ => Some(format!("words {} of the {of}", list(positions))),
        }
    };
    let parts: Vec<String> = [
        part(&repaired.container_words, "container phrase"),
        part(&repaired.card_words, "card"),
    ]
    .into_iter()
    .flatten()
    .collect();
    style::and_list(&parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_repaired_words_are_listed_plainly() {
        let repaired = |container: Vec<usize>, card: Vec<usize>| Repaired {
            container: String::new(),
            container_words: container,
            card_words: card,
            changes: Vec::new(),
        };
        assert_eq!(
            what_was_repaired(&repaired(vec![3], vec![])),
            "Repaired word 3 of the container phrase."
        );
        assert_eq!(
            what_was_repaired(&repaired(vec![3, 9, 17], vec![2])),
            "Repaired words 3, 9 and 17 of the container phrase and word 2 of the card."
        );
    }

    /// The lines said where the repair words are asked for stay on one line each.
    #[test]
    fn the_card_hints_fit_one_line() {
        for line in [
            CARD_HINT,
            NO_CARD_SEARCH_HINT,
            NO_CARD_BACK_HINT,
            NOTHING_TO_REPAIR,
        ] {
            assert!(line.len() <= style::TEXT_WIDTH, "{line}");
        }
    }

    /// No note of a list here is cut with "…".
    #[test]
    fn the_lists_show_whole() {
        assert!(choice::answers_fit(&use_answers()));
    }

    #[test]
    fn the_question_fits_the_screen() {
        assert!(choice::fits(REPAIR_EXPLAINED));
    }
}
