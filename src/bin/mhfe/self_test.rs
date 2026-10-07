//! `mhfe self-test`: every part of this program compared with its known answers on this computer,
//! in a few seconds: the parts the library checks (`mhfe::self_check`, at its full tier, with the
//! operating system's generator) and the protections of this process. Every command that handles
//! a secret runs the quick part of the same checks at its start (startup.rs).
//!
//! With `--vectors` it also runs two published test vectors at their full cost, an encryption of
//! suite 3 and a recovery of suite 4, which take minutes and 2 GiB: a program that passes computes
//! MHFE as the specification says, here and now, also where only the full size shows a fault. The
//! vectors are public, so no secret is involved.

use std::io::{self, IsTerminal};
use std::time::{Duration, Instant};

use anstream::{eprint, eprintln};
use anstyle::Style;
use clap::Args;
use mhfe::operation::Stage;
use mhfe::self_check::{ComponentOutcome, ComponentResult, SelfCheckReport, Tier};
use mhfe::self_test::SelfTest;
#[cfg(test)]
use mhfe::self_test::SelfTestFault;
use mhfe::{WorkFactor, ROUNDS};

use crate::exit::{Failure, INTERNAL_ERROR, SUCCESS};
use crate::flow::{self, Flow, Kind};
use crate::readme;
use crate::settings;
use crate::startup;
use crate::style::{self, paint, BAD, GOOD, MUTED, WARNING};
use crate::system_random::SystemRandom;
use crate::terminal::{self, Input, Progress};

#[derive(Args)]
pub struct Options {
    /// Also run the published vectors at full cost: minutes, 2 GiB
    #[arg(long, long_help = vectors_help())]
    vectors: bool,
}

/// The top of `mhfe self-test --help`.
pub fn about() -> String {
    style::command_about(&[
        "Test every part of this program",
        "Compares every part of this program with its known answers on this computer: the \
         hashes, Argon2id at 1, 64 and 256 MiB, the rounds of the cipher with the published test \
         vectors, the formats, passwords, word lists, repair words, check words, wallet keys and \
         addresses, hidden wallets, rekey, the rehearsal check and the random generator. It also \
         reads back what keeps secrets in this process: no core dumps, the isolation, hidden \
         input and locked memory. It takes a few seconds and up to 256 MiB, and uses no secret.",
        "Every command that handles a secret runs the quick part of these checks at its start, \
         and stops before it asks for anything if one fails.",
    ])
}

fn vectors_help() -> String {
    style::option_help(&[
        "Also run the published vectors at their full cost.",
        &format!(
            "Encrypts the public suite 3 vector zero-12 and recovers the public suite 4 vector \
             same-length-zero-12 at the default settings, 12 rounds each, and compares the \
             results with the published ones. It finds faults that show only at the full size of \
             Argon2's memory. Cost: {}.",
            vectors_cost()
        ),
    ])
}

/// The end of `mhfe self-test --help`.
pub fn help() -> String {
    style::help_section(
        "Examples:",
        &[
            ("mhfe self-test", "Every part, in a few seconds"),
            (
                "mhfe self-test --vectors",
                "Every part and the published vectors",
            ),
        ],
    )
}

/// What the published vectors cost: "about 2 to 4 minutes, 2 GiB", for the help, the report and
/// the menu.
pub fn vectors_cost() -> String {
    const GIB: u64 = 1 << 30;
    const MINUTE: u64 = 60;
    /// An encryption of 12 rounds and a recovery of 12, each estimated as one operation.
    const OPERATIONS: u64 = 2;
    // Both vectors use the default settings, PIM 0 and memory level 0.
    let work = WorkFactor::default();
    let (low, high) = work.estimated_seconds();
    format!(
        "about {} to {} minutes, {} GiB",
        (OPERATIONS * low).div_ceil(MINUTE),
        (OPERATIONS * high).div_ceil(MINUTE),
        work.memory_bytes() / GIB
    )
}

/// The title of `mhfe self-test`.
const TITLE: &str = "Test this program";
/// How the message of a part that stops the program begins.
const FAILED: &str = "Self-test failed";

pub fn run(options: Options) -> Result<i32, Failure> {
    // With the published vectors the work takes minutes: at a terminal it is then a step of its
    // own, as in the commands that run Argon2, and the summary and verdict follow it.
    let flow = options
        .vectors
        .then(|| Flow::start(&Input::terminal_only(), TITLE));
    style::title(TITLE);
    flow::step();
    let started = Instant::now();
    let report = test_every_part();
    let took = started.elapsed();
    show_table(&report_rows(&report));
    // A blank line between the table and the facts below it, whose labels are narrower; kept for
    // the summary too.
    eprintln!();
    flow::keep_shown(Kind::Fact, &[String::new()]);
    style::fact("Time", seconds(took));
    if !options.vectors {
        style::fact(
            "Vectors",
            paint(
                MUTED,
                format!("not run · mhfe self-test --vectors, {}", vectors_cost()),
            ),
        );
    }
    if !report.passed() {
        drop(flow);
        return Ok(alarm(
            "A part of this program does NOT give its known answers.",
        ));
    }
    let Some(flow) = flow else {
        eprintln!();
        style::ok("Every part of this program gives its known answers.");
        return Ok(SUCCESS);
    };
    if run_vectors(flow)? {
        style::ok("This program computes MHFE as the published vectors say.");
        Ok(SUCCESS)
    } else {
        Ok(alarm("This program does NOT compute MHFE as published."))
    }
}

/// Every part at the full tier, with the operating system's generator. At a terminal a status line
/// names the part being tested, as some take a second; it is erased afterwards.
fn test_every_part() -> SelfCheckReport {
    let mut random = SystemRandom;
    let mut set = startup::every_part(Some(&mut random));
    let mut status = Status::new();
    let report = startup::run_named(
        &mut set,
        Tier::Full,
        FAILED,
        &mut |label| status.testing(label),
        &mut |_| {},
    );
    status.erase();
    report
}

/// A line that names the part being tested, redrawn in place; only at a terminal.
struct Status {
    shown: bool,
    /// The widest line drawn, which erasing covers.
    widest: usize,
}

impl Status {
    fn new() -> Self {
        Self {
            shown: io::stderr().is_terminal(),
            widest: 0,
        }
    }

    fn testing(&mut self, label: &str) {
        if !self.shown {
            return;
        }
        let line = format!("  Testing {label}…");
        let width = line.chars().count();
        let padding = " ".repeat(self.widest.saturating_sub(width));
        self.widest = self.widest.max(width);
        eprint!("\r{}{padding}", paint(MUTED, line));
    }

    fn erase(&self) {
        if self.shown && self.widest > 0 {
            eprint!("\r{}\r", " ".repeat(self.widest));
        }
    }
}

/// One row of the report: a part and its outcome.
struct Row {
    label: &'static str,
    style: Style,
    value: String,
}

/// The rows of the parts, in the order they ran.
fn report_rows(report: &SelfCheckReport) -> Vec<Row> {
    report.results().iter().map(part_row).collect()
}

/// "1.4 s" below ten seconds, "12 s" or "1 min 5 s" above.
fn seconds(took: Duration) -> String {
    const SHORT: Duration = Duration::from_secs(10);
    if took < SHORT {
        format!("{:.1} s", took.as_secs_f64())
    } else {
        terminal::duration(took.as_secs())
    }
}

fn part_row(result: &ComponentResult) -> Row {
    let (passed, failed) = verdicts(result.id());
    let (style, value) = match result.outcome() {
        ComponentOutcome::Passed => (GOOD, passed.to_owned()),
        ComponentOutcome::Warning(detail) => (WARNING, format!("! {detail}")),
        ComponentOutcome::NotAvailable(reason) => (MUTED, format!("not available here: {reason}")),
        ComponentOutcome::NotRun(reason) => (MUTED, format!("not run: {reason}")),
        ComponentOutcome::Failed(detail) => (BAD, format!("{failed}: {detail}")),
    };
    Row {
        label: result.label(),
        style,
        value,
    }
}

/// What a part that passed and one that failed are called. Most parts compare known answers; the
/// protections of the process and the generator are in force or healthy instead. The identifiers
/// are those of the checks: protect.rs, hidden_input.rs and the library's random and memory
/// modules.
fn verdicts(id: &str) -> (&'static str, &'static str) {
    match id {
        crate::protect::CORE_DUMPS_ID => ("off", "NOT off"),
        crate::protect::ISOLATION_ID => ("enforced", "NOT enforced"),
        crate::hidden_input::HIDDEN_INPUT_ID => ("echo off", "echo NOT off"),
        "memory-locking" => ("works", "does NOT work"),
        "random-source" => ("healthy", "NOT healthy"),
        _ => ("as published", "NOT as published"),
    }
}

/// Shows the rows with their labels in one column, as wide as the longest, and keeps them for the
/// summary of a command shown one step at a time.
fn show_table(rows: &[Row]) {
    let label_width = rows
        .iter()
        .map(|row| row.label.chars().count())
        .max()
        .unwrap_or(0);
    let lines: Vec<String> = rows
        .iter()
        .flat_map(|row| style::report_row(row.label, label_width, row.style, &row.value))
        .collect();
    for line in &lines {
        eprintln!("{line}");
    }
    flow::keep_shown(Kind::Fact, &lines);
}

/// The verdict of a test that failed; the exit code it ends with.
fn alarm(headline: &str) -> i32 {
    eprintln!();
    style::alarm(
        headline,
        "Do NOT use it for a real phrase; try another computer or build.",
    );
    style::more(readme::SELF_TEST);
    INTERNAL_ERROR
}

/// Runs the two published vectors at their full cost and shows how each came out; whether both
/// came out as published.
fn run_vectors(flow: Flow) -> Result<bool, Failure> {
    let test = SelfTest::published()?;
    // Both vectors use the default settings, PIM 0 and memory level 0.
    let work = WorkFactor::default();
    style::fact(
        "Vectors",
        format!(
            "{} (suite 3) and {} (suite 4) {}",
            test.suite_3_vector(),
            test.suite_4_vector(),
            paint(MUTED, "public")
        ),
    );
    style::fact("Cost", vectors_cost());
    let mut progress = Progress::start();
    let mut mhfe = settings::reserve_memory(work)?;
    let mut recovering = false;
    // The terminal shows the encryption's rounds of 24, then the recovery's of 12, as two parts.
    let result = test.run(&mut mhfe, &mut |stage, round, rounds| {
        if stage == Stage::Recover {
            if !recovering {
                recovering = true;
                progress.next_operation();
            }
            progress.round_starts(round - ROUNDS, ROUNDS);
        } else {
            progress.round_starts(round, rounds);
        }
        Ok(())
    })?;
    progress.finish();
    flow.finish();

    eprintln!();
    let verdict = |ok: bool| {
        if ok {
            paint(GOOD, "as published")
        } else {
            paint(BAD, "NOT as published")
        }
    };
    style::fact(
        "Suite 3",
        format!("encrypts {}", verdict(result.suite_3_as_published())),
    );
    style::fact(
        "Suite 4",
        format!("recovers {}", verdict(result.suite_4_as_published())),
    );
    // Where it left the published path: before Argon2id, in Argon2id, or after its last call. The
    // library words it, so that the browser package says the same.
    if let Some(fault) = result.fault() {
        style::fact_wrapped("Fault", &fault.to_string());
    }
    eprintln!();
    Ok(result.passed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn plain(line: &str) -> String {
        let mut text = String::new();
        let mut in_code = false;
        for character in line.chars() {
            match character {
                '\u{1b}' => in_code = true,
                'm' if in_code => in_code = false,
                _ if in_code => {}
                _ => text.push(character),
            }
        }
        text
    }

    /// The full self-test passes on this computer, every part once, and fits the text width. It
    /// scans every Unicode scalar value and runs Argon2 at 256 MiB, about two seconds in a release
    /// build and ten in a debug one, so it runs on request, as the library's own test of the full
    /// set: `cargo test --release --bins -- --ignored every_part_passes_the_full_self_test`.
    #[test]
    #[ignore = "the whole full self-test: seconds and 256 MiB"]
    fn every_part_passes_the_full_self_test() {
        let _alone = startup::one_test_at_a_time();
        crate::protect::harden_process();
        let started = Instant::now();
        let report = test_every_part();
        assert!(report.passed(), "{:?}", report.first_failure());
        let ids: Vec<&str> = report.results().iter().map(ComponentResult::id).collect();
        assert_eq!(ids, startup::every_part(None).ids());
        assert!(
            ids.contains(&"argon2-sizes"),
            "the full tier runs the larger Argon2 sizes"
        );
        let rows = report_rows(&report);
        assert!(started.elapsed().as_secs() < 600);
        let label_width = rows.iter().map(|row| row.label.len()).max().unwrap();
        for row in &rows {
            for line in style::report_row(row.label, label_width, row.style, &row.value) {
                assert!(plain(&line).chars().count() <= style::TEXT_WIDTH, "{line}");
            }
        }
        let cipher = rows
            .iter()
            .find(|row| row.label == "Cipher rounds")
            .unwrap();
        assert_eq!(cipher.value, "as published");
    }

    #[test]
    fn each_outcome_reads_as_its_kind() {
        let mut set = mhfe::self_check::SelfCheck::new()
            .with(Fixed(
                "cipher-rounds",
                ComponentOutcome::Failed("vector 4 of 10 gives another container".into()),
            ))
            .with(Fixed(
                crate::protect::CORE_DUMPS_ID,
                ComponentOutcome::Passed,
            ))
            .with(Fixed(
                "memory-locking",
                ComponentOutcome::Warning("the system refused".into()),
            ))
            .with(Fixed(
                crate::hidden_input::HIDDEN_INPUT_ID,
                ComponentOutcome::NotAvailable("standard input is not a terminal".into()),
            ))
            .with(Fixed("argon2", ComponentOutcome::NotRun("left out".into())));
        let report = set.run_quietly(Tier::Full);
        let rows = report_rows(&report);
        let values: Vec<&str> = rows.iter().map(|row| row.value.as_str()).collect();
        assert_eq!(
            values,
            [
                "NOT as published: vector 4 of 10 gives another container",
                "off",
                "! the system refused",
                "not available here: standard input is not a terminal",
                "not run: left out",
            ]
        );
        assert_eq!(rows[0].style, BAD);
        assert_eq!(rows[1].style, GOOD);
        assert_eq!(rows[2].style, WARNING);
        assert_eq!(rows[3].style, MUTED);
    }

    struct Fixed(&'static str, ComponentOutcome);

    impl mhfe::self_check::ComponentCheck for Fixed {
        fn id(&self) -> &'static str {
            self.0
        }

        fn label(&self) -> &'static str {
            "Fixed"
        }

        fn run(&mut self, _: Tier) -> ComponentOutcome {
            self.1.clone()
        }
    }

    /// The fault line tells a fault before Argon2id, in it and after it apart, wrapped under its
    /// column within the text width. The library's tests inject each fault into a real run.
    #[test]
    fn each_fault_is_named_as_its_kind() {
        let lines = |fault: SelfTestFault| -> Vec<String> {
            style::fact_lines("Fault", &fault.to_string())
                .iter()
                .map(|line| plain(line))
                .collect()
        };
        assert_eq!(
            lines(SelfTestFault::Argon2Input { round: 4 }),
            [
                "  Fault      first wrong round 4 of 24: Argon2id was given an input that the",
                "             published vector does not have, so the fault is before Argon2id,",
                "             in this round's password or salt or in the state before it",
            ]
        );
        assert_eq!(
            lines(SelfTestFault::Argon2Key { round: 14 }),
            [
                "  Fault      first wrong round 14 of 24: Argon2id returned another key for the",
                "             published input, so the fault is in Argon2id",
            ]
        );
        assert_eq!(
            lines(SelfTestFault::AfterArgon2),
            [
                "  Fault      every Argon2id input and key as published, so the fault is after",
                "             the last Argon2id call of an operation",
            ]
        );
        for fault in [
            SelfTestFault::Argon2Input { round: 24 },
            SelfTestFault::Argon2Key { round: 24 },
            SelfTestFault::AfterArgon2,
        ] {
            for line in lines(fault) {
                assert!(line.chars().count() <= style::TEXT_WIDTH, "{line}");
            }
        }
    }

    #[test]
    fn the_vectors_run_only_on_request() {
        let parse = |arguments: &[&str]| {
            let typed = std::iter::once("mhfe").chain(arguments.iter().copied());
            match crate::Cli::try_parse_from(typed).unwrap().command {
                crate::Command::SelfTest(options) => options.vectors,
                _ => unreachable!("not the self-test"),
            }
        };
        assert!(!parse(&["self-test"]));
        assert!(parse(&["self-test", "--vectors"]));
        assert!(
            vectors_cost().ends_with("minutes, 2 GiB"),
            "{}",
            vectors_cost()
        );
    }

    #[test]
    fn durations_read_in_seconds() {
        assert_eq!(seconds(Duration::from_millis(1449)), "1.4 s");
        assert_eq!(seconds(Duration::from_secs(65)), "1 min 5 s");
    }
}
