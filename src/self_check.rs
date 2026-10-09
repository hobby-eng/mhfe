//! Self-checks: every part of the program compared with its known answers, so that a broken build,
//! a faulty processor or memory, or a damaged table shows before anything secret is asked.
//!
//! Each part brings its own check ([`ComponentCheck`]) in a `known_answers` module next to its
//! code, built only with that part; [`sets`] gathers them for each front end. A check compares
//! exact output with published test vectors, or with values from an independent implementation
//! that first reproduced a published vector, and gives each verifier a case it must refuse.
//!
//! Two tiers: [`Tier::Startup`] runs at every start in milliseconds, without Argon2 at full size
//! and without live randomness; [`Tier::Full`] adds the slower cases for a self-test the person
//! asks for. MHFE's own published vectors at their full cost take minutes and gigabytes and stay
//! in [`crate::self_test`].
//!
//! This module holds no vector and knows no feature: it only runs checks and collects their
//! outcomes. It measures no time, since a clock is not available everywhere the library runs.

use crate::MhfeError;

pub mod sets;

/// How much a self-check runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// The quick known answers of every start: milliseconds per part, before any secret is asked.
    Startup,
    /// Every startup case and the slower ones, for the self-test a person runs on request.
    Full,
}

impl Tier {
    /// The name the browser API uses: "startup" or "full".
    pub fn name(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Full => "full",
        }
    }

    /// The tier of a name the browser API uses; another name is [`MhfeError::InvalidRequest`].
    pub fn from_name(name: &str) -> Result<Self, MhfeError> {
        match name {
            "startup" => Ok(Self::Startup),
            "full" => Ok(Self::Full),
            other => Err(MhfeError::InvalidRequest(format!(
                "a self-check tier is \"startup\" or \"full\", not {}",
                crate::error::quoted(other)
            ))),
        }
    }
}

/// What a check found. A detail never holds a secret, a coin's name, a vector's text or the text
/// of an [`MhfeError`]: it names a case by its number and what differed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComponentOutcome {
    /// Every case gave its known answer.
    Passed,
    /// The part works, but a protection around it is weaker than it should be.
    Warning(String),
    /// The part cannot be checked here, for the reason given; it is not a failure.
    NotAvailable(String),
    /// The part was not checked in this run, for the reason given.
    NotRun(String),
    /// A case gave another answer, or the part could not compute it: do not use the program.
    Failed(String),
}

impl From<Result<(), String>> for ComponentOutcome {
    /// A part that passed, or failed with the detail it gives.
    fn from(result: Result<(), String>) -> Self {
        match result {
            Ok(()) => Self::Passed,
            Err(detail) => Self::Failed(detail),
        }
    }
}

impl ComponentOutcome {
    /// The name the browser API uses: "passed", "warning", "notAvailable", "notRun" or "failed".
    pub fn name(&self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Warning(_) => "warning",
            Self::NotAvailable(_) => "notAvailable",
            Self::NotRun(_) => "notRun",
            Self::Failed(_) => "failed",
        }
    }

    /// The reason or the case that differed; none for a pass.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Passed => None,
            Self::Warning(detail)
            | Self::NotAvailable(detail)
            | Self::NotRun(detail)
            | Self::Failed(detail) => Some(detail),
        }
    }

    /// Whether the program must not be used: only [`ComponentOutcome::Failed`].
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

/// The self-check of one part of the program.
pub trait ComponentCheck {
    /// A stable identifier, such as "repair-words", for scripts and the browser API.
    fn id(&self) -> &'static str;

    /// The name a person reads, such as "Repair words (MHFE-REPAIR-1)". It names no coin.
    fn label(&self) -> &'static str;

    /// Whether the check belongs to `tier`; a check of the full self-test only says no to
    /// [`Tier::Startup`].
    fn runs_at(&self, tier: Tier) -> bool {
        let _ = tier;
        true
    }

    /// Runs the cases of `tier` and tells what they gave.
    fn run(&mut self, tier: Tier) -> ComponentOutcome;
}

impl<C: ComponentCheck + ?Sized> ComponentCheck for Box<C> {
    fn id(&self) -> &'static str {
        (**self).id()
    }

    fn label(&self) -> &'static str {
        (**self).label()
    }

    fn runs_at(&self, tier: Tier) -> bool {
        (**self).runs_at(tier)
    }

    fn run(&mut self, tier: Tier) -> ComponentOutcome {
        (**self).run(tier)
    }
}

/// The outcome of one part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentResult {
    id: &'static str,
    label: &'static str,
    outcome: ComponentOutcome,
}

impl ComponentResult {
    pub fn id(&self) -> &'static str {
        self.id
    }

    pub fn label(&self) -> &'static str {
        self.label
    }

    pub fn outcome(&self) -> &ComponentOutcome {
        &self.outcome
    }
}

/// The outcomes of one run, in the order the checks ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfCheckReport {
    tier: Tier,
    results: Vec<ComponentResult>,
}

impl SelfCheckReport {
    pub fn tier(&self) -> Tier {
        self.tier
    }

    pub fn results(&self) -> &[ComponentResult] {
        &self.results
    }

    /// Whether no part failed. A warning, a part not available here and a part not run do not
    /// fail the run.
    pub fn passed(&self) -> bool {
        self.first_failure().is_none()
    }

    /// The first part that failed, if any.
    pub fn first_failure(&self) -> Option<&ComponentResult> {
        self.results
            .iter()
            .find(|result| result.outcome.is_failure())
    }

    /// The parts that work with a weaker protection than they should have.
    pub fn warnings(&self) -> impl Iterator<Item = &ComponentResult> {
        self.results
            .iter()
            .filter(|result| matches!(result.outcome, ComponentOutcome::Warning(_)))
    }

    /// `Ok` when no part failed, else [`MhfeError::SelfCheckFailed`] for the first that did: what
    /// a front end returns before it asks for anything secret.
    pub fn require_passed(&self) -> Result<(), MhfeError> {
        match self.first_failure() {
            None => Ok(()),
            Some(failed) => Err(MhfeError::SelfCheckFailed {
                component: failed.label.to_owned(),
                detail: failed.outcome.detail().unwrap_or_default().to_owned(),
            }),
        }
    }
}

/// The message of a part that failed, as every front end says it: what failed (such as "the
/// self-test failed"), the part's label and the detail, and the advice to stop. A detail that ends
/// a sentence of its own, as a browser's error text may, keeps one period (AUD-015-UI005).
pub fn failure_message(what: &str, label: &str, detail: &str) -> String {
    let detail = detail.trim_end_matches('.');
    format!("{what}: {label}: {detail}. Do not use this program on this computer")
}

/// Called with the identifier and the label of each check just before it runs, so that a front
/// end can name the part if the program stops inside it.
pub type StartCallback<'a> = &'a mut dyn FnMut(&'static str, &'static str);
/// Called with the outcome of each check as soon as it is known.
pub type ResultCallback<'a> = &'a mut dyn FnMut(&ComponentResult);

/// A set of checks, each part once, run in the order they were added.
#[derive(Default)]
pub struct SelfCheck<'a> {
    checks: Vec<Box<dyn ComponentCheck + 'a>>,
}

impl<'a> SelfCheck<'a> {
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// Adds `check`, unless a check with its identifier is in the set already.
    pub fn with(mut self, check: impl ComponentCheck + 'a) -> Self {
        if !self.contains(check.id()) {
            self.checks.push(Box::new(check));
        }
        self
    }

    /// Adds the checks of `other` that this set does not have yet, in their order.
    pub fn merge(mut self, other: SelfCheck<'a>) -> Self {
        for check in other.checks {
            if !self.contains(check.id()) {
                self.checks.push(check);
            }
        }
        self
    }

    /// Leaves out the checks with these identifiers, such as parts that another module of the
    /// same page has checked already.
    pub fn skip(mut self, ids: &[&str]) -> Self {
        self.checks.retain(|check| !ids.contains(&check.id()));
        self
    }

    /// The identifiers of the checks, in their order.
    pub fn ids(&self) -> Vec<&'static str> {
        self.checks.iter().map(|check| check.id()).collect()
    }

    pub fn contains(&self, id: &str) -> bool {
        self.checks.iter().any(|check| check.id() == id)
    }

    pub fn len(&self) -> usize {
        self.checks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }

    /// Runs every check that belongs to `tier`, in order, and reports each one as it starts and
    /// as it ends. A check that does not belong to the tier is left out of the report.
    pub fn run(
        &mut self,
        tier: Tier,
        on_start: StartCallback<'_>,
        on_result: ResultCallback<'_>,
    ) -> SelfCheckReport {
        let mut results = Vec::with_capacity(self.checks.len());
        for check in self.checks.iter_mut().filter(|check| check.runs_at(tier)) {
            on_start(check.id(), check.label());
            let result = ComponentResult {
                id: check.id(),
                label: check.label(),
                outcome: check.run(tier),
            };
            on_result(&result);
            results.push(result);
        }
        SelfCheckReport { tier, results }
    }

    /// [`SelfCheck::run`] without reports along the way.
    pub fn run_quietly(&mut self, tier: Tier) -> SelfCheckReport {
        self.run(tier, &mut |_, _| {}, &mut |_| {})
    }
}

/// Collects the cases of a check: passed when every case gave its known answer, else failed with
/// the first difference, named by its place in its list as "vector 4 of 10 gives another
/// container". Once a case differs, the later ones are not run.
#[derive(Default)]
pub(crate) struct Findings {
    failure: Option<String>,
}

impl Findings {
    pub(crate) fn new() -> Self {
        Self { failure: None }
    }

    /// Runs `check` on every item of a list whose items a person would call `noun`s.
    pub(crate) fn each<T>(
        &mut self,
        noun: &str,
        items: &[T],
        mut check: impl FnMut(&T) -> Result<(), String>,
    ) {
        for (index, item) in items.iter().enumerate() {
            if self.failure.is_some() {
                return;
            }
            if let Err(what) = check(item) {
                self.failure = Some(format!("{noun} {} of {} {what}", index + 1, items.len()));
            }
        }
    }

    /// Records one check that is not part of a list, such as a digest of a whole table.
    pub(crate) fn one(&mut self, check: impl FnOnce() -> Result<(), String>) {
        if self.failure.is_none() {
            if let Err(what) = check() {
                self.failure = Some(what);
            }
        }
    }

    pub(crate) fn outcome(self) -> ComponentOutcome {
        match self.failure {
            None => ComponentOutcome::Passed,
            Some(detail) => ComponentOutcome::Failed(detail),
        }
    }
}

/// `Ok` when `same`, else `Err(what)`: one comparison of a case.
pub(crate) fn expect(same: bool, what: &str) -> Result<(), String> {
    if same {
        Ok(())
    } else {
        Err(what.to_owned())
    }
}

/// `Ok` when `result` is the refusal with the error code `code`, as a verifier must give for a
/// case it must refuse; else what it gave instead, by error code only.
pub(crate) fn expect_refusal<T>(result: Result<T, MhfeError>, code: &str) -> Result<(), String> {
    match result {
        Err(error) if error.code() == code => Ok(()),
        Err(error) => Err(format!(
            "is refused with {} instead of {code}",
            error.code()
        )),
        Ok(_) => Err(format!("is accepted instead of refused with {code}")),
    }
}

/// What a case that should have worked gave instead: its error code only, since an error's text
/// may hold a vector's words.
pub(crate) fn stopped(error: MhfeError) -> String {
    format!("stops with {}", error.code())
}

/// A digest or message authentication code compared with its published value. The function is
/// part of the case, so that a test can give a wrong one.
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-wallet"
))]
#[derive(Clone, Copy)]
pub(crate) struct DigestCase {
    /// The algorithm's name, which the detail of a failure gives.
    pub(crate) algorithm: &'static str,
    /// The function under test, given the key (empty for a plain hash) and the message.
    pub(crate) function: fn(&[u8], &[u8]) -> Vec<u8>,
    pub(crate) key: &'static [u8],
    pub(crate) message: &'static [u8],
    /// The published value, in hexadecimal.
    pub(crate) expected: &'static str,
}

/// Runs digest cases: a failure names the algorithm, as "SHA-256 gives another digest".
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-wallet"
))]
pub(crate) fn digest_outcome(cases: &[DigestCase]) -> ComponentOutcome {
    let mut findings = Findings::new();
    for case in cases {
        findings.one(|| {
            let digest = (case.function)(case.key, case.message);
            expect(
                hex::encode(digest) == case.expected,
                &format!("{} gives another digest", case.algorithm),
            )
        });
    }
    findings.outcome()
}

/// Test data that lives as long as the test binary, as the checks hold their vectors.
#[cfg(test)]
pub(crate) fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

/// Asserts that `check`, made with a damaged vector, fails at startup with `detail`.
#[cfg(test)]
pub(crate) fn fails_with(mut check: impl ComponentCheck, detail: &str) {
    assert_eq!(
        check.run(Tier::Startup),
        ComponentOutcome::Failed(detail.to_owned())
    );
}

/// The container phrase of the suite 3 vector zero-12 (vectors/suite3/zero-12.json), the public
/// all-zero 12-word phrase under the public test password: the container the known answers of the
/// repair words and of the search for missing words use. A unit test compares it with the vector.
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-repair"
))]
pub(crate) const ZERO_12_CONTAINER: &str =
    "donate stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also nerve \
     cycle famous provide heart ahead chunk caution peace";

/// Decodes a hexadecimal constant at compile time; a malformed one stops the build.
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) const fn hex<const N: usize>(text: &str) -> [u8; N] {
    let digits = text.as_bytes();
    assert!(
        digits.len() == 2 * N,
        "a hexadecimal constant has the wrong length"
    );
    let mut bytes = [0u8; N];
    let mut index = 0;
    while index < N {
        bytes[index] = nibble(digits[2 * index]) << 4 | nibble(digits[2 * index + 1]);
        index += 1;
    }
    bytes
}

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
const fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => panic!("a hexadecimal constant holds a character other than 0-9 and a-f"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A check that gives a fixed outcome and counts its runs.
    struct Fixed {
        id: &'static str,
        full_only: bool,
        outcome: ComponentOutcome,
        runs: usize,
    }

    impl Fixed {
        fn new(id: &'static str, outcome: ComponentOutcome) -> Self {
            Self {
                id,
                full_only: false,
                outcome,
                runs: 0,
            }
        }
    }

    impl ComponentCheck for Fixed {
        fn id(&self) -> &'static str {
            self.id
        }

        fn label(&self) -> &'static str {
            "Fixed"
        }

        fn runs_at(&self, tier: Tier) -> bool {
            !self.full_only || tier == Tier::Full
        }

        fn run(&mut self, _: Tier) -> ComponentOutcome {
            self.runs += 1;
            self.outcome.clone()
        }
    }

    #[test]
    fn startup_leaves_out_the_checks_of_the_full_tier_only() {
        let mut slow = Fixed::new("slow", ComponentOutcome::Passed);
        slow.full_only = true;
        let mut set = SelfCheck::new()
            .with(Fixed::new("quick", ComponentOutcome::Passed))
            .with(slow);
        let startup = set.run_quietly(Tier::Startup);
        let ids: Vec<&str> = startup.results().iter().map(ComponentResult::id).collect();
        assert_eq!(ids, ["quick"]);
        assert_eq!(startup.tier(), Tier::Startup);
        let full = set.run_quietly(Tier::Full);
        let ids: Vec<&str> = full.results().iter().map(ComponentResult::id).collect();
        assert_eq!(ids, ["quick", "slow"]);
    }

    #[test]
    fn each_part_runs_once_in_the_order_it_was_added() {
        let first = SelfCheck::new()
            .with(Fixed::new("a", ComponentOutcome::Passed))
            .with(Fixed::new("b", ComponentOutcome::Passed))
            .with(Fixed::new(
                "a",
                ComponentOutcome::Failed("second a".to_owned()),
            ));
        let second = SelfCheck::new()
            .with(Fixed::new("c", ComponentOutcome::Passed))
            .with(Fixed::new(
                "b",
                ComponentOutcome::Failed("second b".to_owned()),
            ));
        let mut set = first.merge(second);
        assert_eq!(set.ids(), ["a", "b", "c"]);
        assert!(set.run_quietly(Tier::Startup).passed());
        let mut skipped = set.skip(&["b", "unknown"]);
        assert_eq!(skipped.ids(), ["a", "c"]);
        assert_eq!(skipped.len(), 2);
        assert!(!skipped.is_empty());
        assert_eq!(skipped.run_quietly(Tier::Full).results().len(), 2);
    }

    #[test]
    fn only_a_failure_fails_the_run() {
        let mut set = SelfCheck::new()
            .with(Fixed::new("passed", ComponentOutcome::Passed))
            .with(Fixed::new(
                "warning",
                ComponentOutcome::Warning("weaker".to_owned()),
            ))
            .with(Fixed::new(
                "absent",
                ComponentOutcome::NotAvailable("not here".to_owned()),
            ))
            .with(Fixed::new(
                "skipped",
                ComponentOutcome::NotRun("not asked".to_owned()),
            ));
        let report = set.run_quietly(Tier::Full);
        assert!(report.passed());
        assert_eq!(report.require_passed(), Ok(()));
        let warnings: Vec<&str> = report.warnings().map(ComponentResult::id).collect();
        assert_eq!(warnings, ["warning"]);
        let names: Vec<&str> = report
            .results()
            .iter()
            .map(|result| result.outcome().name())
            .collect();
        assert_eq!(names, ["passed", "warning", "notAvailable", "notRun"]);

        let mut failing = SelfCheck::new()
            .with(Fixed::new("first", ComponentOutcome::Passed))
            .with(Fixed::new(
                "broken",
                ComponentOutcome::Failed("case 2 of 3 differs".to_owned()),
            ))
            .with(Fixed::new(
                "later",
                ComponentOutcome::Failed("x".to_owned()),
            ));
        let report = failing.run_quietly(Tier::Startup);
        assert!(!report.passed());
        assert_eq!(
            report.first_failure().map(ComponentResult::id),
            Some("broken")
        );
        let error = report.require_passed().unwrap_err();
        assert_eq!(error.code(), "SELF_CHECK_FAILED");
        assert_eq!(
            error,
            MhfeError::SelfCheckFailed {
                component: "Fixed".to_owned(),
                detail: "case 2 of 3 differs".to_owned(),
            }
        );
    }

    #[test]
    fn every_check_is_reported_as_it_starts_and_ends() {
        let mut set = SelfCheck::new()
            .with(Fixed::new("a", ComponentOutcome::Passed))
            .with(Fixed::new("b", ComponentOutcome::Failed("x".to_owned())));
        let mut events = Vec::new();
        let events_cell = std::cell::RefCell::new(&mut events);
        set.run(
            Tier::Startup,
            &mut |id, label| events_cell.borrow_mut().push(format!("start {id} {label}")),
            &mut |result| {
                events_cell.borrow_mut().push(format!(
                    "end {} {}",
                    result.id(),
                    result.outcome().name()
                ))
            },
        );
        assert_eq!(
            events,
            [
                "start a Fixed",
                "end a passed",
                "start b Fixed",
                "end b failed"
            ]
        );
    }

    #[test]
    fn tiers_have_the_names_of_the_browser_api() {
        for tier in [Tier::Startup, Tier::Full] {
            assert_eq!(Tier::from_name(tier.name()), Ok(tier));
        }
        assert_eq!(
            Tier::from_name("nightly").unwrap_err().code(),
            "INVALID_REQUEST"
        );
    }

    #[test]
    fn findings_name_the_first_difference_by_its_place() {
        let mut findings = Findings::new();
        let mut checked = Vec::new();
        findings.each("vector", &[1, 2, 3], |&number| {
            checked.push(number);
            expect(number != 2, "gives another container")
        });
        findings.one(|| Err("never reached".to_owned()));
        assert_eq!(checked, [1, 2], "nothing runs after the first difference");
        assert_eq!(
            findings.outcome(),
            ComponentOutcome::Failed("vector 2 of 3 gives another container".to_owned())
        );
        assert_eq!(Findings::new().outcome(), ComponentOutcome::Passed);
    }

    #[test]
    fn a_refusal_must_be_the_expected_one() {
        let refused: Result<(), MhfeError> = Err(MhfeError::VerifierMismatch);
        assert_eq!(expect_refusal(refused.clone(), "VERIFIER_MISMATCH"), Ok(()));
        assert_eq!(
            expect_refusal(refused, "VERIFICATION_FAILED"),
            Err("is refused with VERIFIER_MISMATCH instead of VERIFICATION_FAILED".to_owned())
        );
        assert_eq!(
            expect_refusal(Ok(()), "VERIFIER_MISMATCH"),
            Err("is accepted instead of refused with VERIFIER_MISMATCH".to_owned())
        );
    }

    #[test]
    fn a_wrong_digest_function_names_its_algorithm() {
        fn empty(_: &[u8], _: &[u8]) -> Vec<u8> {
            Vec::new()
        }
        let case = DigestCase {
            algorithm: "Nothing",
            function: empty,
            key: b"",
            message: b"abc",
            expected: "",
        };
        assert_eq!(digest_outcome(&[case]), ComponentOutcome::Passed);
        let wrong = DigestCase {
            expected: "00",
            ..case
        };
        assert_eq!(
            digest_outcome(&[case, wrong]),
            ComponentOutcome::Failed("Nothing gives another digest".to_owned())
        );
    }

    #[test]
    fn hexadecimal_constants_decode_at_compile_time() {
        const BYTES: [u8; 3] = hex("00a1ff");
        assert_eq!(BYTES, [0x00, 0xa1, 0xff]);
    }
}
