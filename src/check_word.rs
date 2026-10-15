//! The password check word, the optional profile MHFE-PASSWORD-CHECK-1 of the specification
//! (README, "Optional password check word"). Five words drawn from the EFF large wordlist get a
//! sixth computed from them; the six words are the password. The check word lets a program notice
//! and repair a typing error before any Argon2 work: one forgotten or unreadable word at a known
//! place, the check word included, is restored uniquely; one wrong word is noticed, but not where
//! it is.
//!
//! The five drawn words carry about 64.6 bits; the check word adds none and is as secret as the
//! rest. A check word that fits shows only that the six words belong together, never that the
//! password opens a given container.

use std::convert::Infallible;
use std::ops::Range;

use zeroize::Zeroizing;

use crate::eff::{EffList, LIST_SIZE};
use crate::memory::LockedText;

#[cfg(test)]
use crate::Password;

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-passwords"
))]
pub(crate) mod known_answers;

/// An explicit correction or repair that this review did not offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewError {
    /// The explicit choice was absent from this review.
    NotOffered,
    /// The caller supplied a review-choice name the profile does not offer.
    UnknownChoice,
    /// A drawn word's index is outside the EFF list.
    InvalidIndex,
}
impl ReviewError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> crate::ErrorCode {
        match self {
            Self::NotOffered => crate::ErrorCode::PasswordRepairNotOffered,
            Self::UnknownChoice | Self::InvalidIndex => crate::ErrorCode::InvalidRequest,
        }
    }
    /// The machine-readable refusal code.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl std::fmt::Display for ReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotOffered => "the review of this password did not offer that choice",
            Self::UnknownChoice => "invalid request: unknown password choice",
            Self::InvalidIndex => "invalid request: password word index is outside the EFF list",
        })
    }
}
impl std::error::Error for ReviewError {}

/// The profile's name in the specification.
pub const PROFILE: &str = "MHFE-PASSWORD-CHECK-1";
/// The words drawn at random, before the check word.
pub const DRAWN_WORDS: usize = 5;
/// The weights of the five drawn words, each coprime to 7,776, which is what makes one erased word
/// recoverable and one wrong word noticeable.
const WEIGHTS: [usize; DRAWN_WORDS] = [1, 5, 7, 11, 13];
/// What a person types for a word they cannot read; any other word outside the list counts the
/// same, but this one says it on purpose.
pub const UNREADABLE: &str = "?";

impl PasswordReview {
    /// The index of the check word for the indexes of the five drawn words:
    /// (d1 + 5 d2 + 7 d3 + 11 d4 + 13 d5) mod 7776.
    ///
    /// Every index must be below 7,776; otherwise [`ReviewError::InvalidIndex`] is returned
    /// before arithmetic. This method needs no textual review or password copy.
    pub fn check_index(drawn: &[usize; DRAWN_WORDS]) -> Result<usize, ReviewError> {
        if drawn.iter().any(|&index| index >= LIST_SIZE) {
            return Err(ReviewError::InvalidIndex);
        }
        Ok(weighted_index(drawn))
    }
}

/// Only validated EFF indexes enter this arithmetic: at most 7,775 * 13 per product.
fn weighted_index(drawn: &[usize; DRAWN_WORDS]) -> usize {
    drawn
        .iter()
        .zip(WEIGHTS)
        .map(|(&index, weight)| index * weight % LIST_SIZE)
        .sum::<usize>()
        % LIST_SIZE
}

/// What a password is under the profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reading {
    /// Not six words of the list with at most one gap: the profile does not apply to it.
    NotThisShape,
    /// The six words fit together.
    Fits,
    /// One word was left out or is not in the list; the check word restores it.
    Restorable,
    /// All six words are in the list but do not fit: one is wrong, at a place that cannot be told.
    ///
    /// Each place allows exactly one repair, so there are six.
    Mismatch,
}

/// How the written form of a password differs from the text typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Correction {
    /// Spaces before, after or between the words were removed.
    ExtraSpaces,
    /// Capital letters were made small.
    Capitals,
    /// Both: extra spaces removed and capitals made small.
    SpacesAndCapitals,
}

impl Correction {
    /// What the correction does, in the words the tools show.
    pub fn text(self) -> &'static str {
        match self {
            Self::ExtraSpaces => "extra spaces removed",
            Self::Capitals => "capitals made small",
            Self::SpacesAndCapitals => "spaces and capitals corrected",
        }
    }
}

/// One word of the reviewed password replaced so that the six fit. Its Debug text gives the place
/// only: the word and where it was typed are parts of the password (AUD-024-SEC006).
#[derive(Clone, PartialEq, Eq)]
pub struct Repair {
    position: usize,
    word: &'static str,
    /// Where the word as typed lies in the reviewed text.
    typed: Range<usize>,
}

impl std::fmt::Debug for Repair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repair")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl Repair {
    /// The place of the word, from 1; 6 is the check word.
    pub fn position(&self) -> usize {
        self.position
    }

    /// The word it becomes.
    pub fn word(&self) -> &'static str {
        self.word
    }
}

/// A choice for a reviewed password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewChoice {
    /// The password exactly as typed.
    AsTyped,
    /// The written form, which fits; offered when the review has a correction and no repairs.
    Corrected,
    /// The repair at this place, from 1, applied to the reviewed text.
    Repair(usize),
}

/// The review of a typed password under the profile. A password typed with extra spaces or
/// capitals is read in the profile's written form when that is of the profile's shape. Every
/// correction and repair is used only when chosen, and the password as typed is always a choice:
/// a container does not record whether its password has a check word.
pub struct PasswordReview {
    typed: LockedText,
    written: Option<(LockedText, Correction)>,
    reading: Reading,
    repairs: Vec<Repair>,
}

impl PasswordReview {
    /// Reviews `typed`. The text is copied once, locked, and wiped with the review.
    pub fn of(typed: &str) -> Self {
        let list = EffList::get();
        let typed = LockedText::copy_of(typed);
        let (reading, repairs) = read(list, &typed);
        if reading != Reading::NotThisShape {
            return Self {
                typed,
                written: None,
                reading,
                repairs,
            };
        }
        match written_form(&typed) {
            Some((form, correction)) => {
                let (reading, repairs) = read(list, &form);
                let written = (reading != Reading::NotThisShape).then_some((form, correction));
                Self {
                    typed,
                    written,
                    reading,
                    repairs,
                }
            }
            None => Self {
                typed,
                written: None,
                reading,
                repairs,
            },
        }
    }

    /// The reading of the reviewed text: the written form when there is a correction.
    pub fn reading(&self) -> Reading {
        self.reading
    }

    /// How the reviewed text differs from the text typed, if it does.
    pub fn correction(&self) -> Option<Correction> {
        self.written.as_ref().map(|(_, correction)| *correction)
    }

    /// The repairs offered: one for a restorable word, six for a mismatch, else none.
    pub fn repairs(&self) -> &[Repair] {
        &self.repairs
    }

    /// The word as typed that `repair` replaces: "?" or another word outside the list for a
    /// restorable word.
    pub fn typed_word(&self, repair: &Repair) -> &str {
        &self.reviewed()[repair.typed.clone()]
    }

    /// Whether the repairs, or the correction, should be offered before the password as typed.
    ///
    /// A word typed as "?" asks for the repair, and a corrected password that fits is strong
    /// evidence of the profile. Any other word may belong to a password made without a check
    /// word, which is used as typed unless a repair is chosen.
    pub fn repairs_first(&self) -> bool {
        self.repairs
            .iter()
            .any(|repair| self.typed_word(repair) == UNREADABLE)
            || (self.repairs.is_empty() && self.offers_correction())
    }

    /// Whether [`ReviewChoice::Corrected`] is offered: a written form that fits as it is.
    pub fn offers_correction(&self) -> bool {
        self.written.is_some() && self.reading == Reading::Fits
    }

    /// The password for `choice`, built at its final size and locked.
    pub fn apply(&self, choice: ReviewChoice) -> Result<LockedText, ReviewError> {
        match choice {
            ReviewChoice::AsTyped => Ok(LockedText::copy_of(&self.typed)),
            ReviewChoice::Corrected if self.offers_correction() => {
                Ok(LockedText::copy_of(self.reviewed()))
            }
            ReviewChoice::Repair(position) => self
                .repairs
                .iter()
                .find(|repair| repair.position == position)
                .map(|repair| repaired(self.reviewed(), repair))
                .ok_or(ReviewError::NotOffered),
            ReviewChoice::Corrected => Err(ReviewError::NotOffered),
        }
    }

    /// The password a person typed for a new container or wallet, after the review choice they made:
    /// `choice` applies a correction or repair the review offered, and `None` keeps the text as typed.
    pub fn choose(typed: &str, choice: Option<ReviewChoice>) -> Result<LockedText, ReviewError> {
        match choice {
            None | Some(ReviewChoice::AsTyped) => Ok(LockedText::copy_of(typed)),
            Some(choice) => PasswordReview::of(typed).apply(choice),
        }
    }

    /// The text the reading is of.
    fn reviewed(&self) -> &str {
        self.written.as_ref().map_or(&*self.typed, |(form, _)| form)
    }
}

/// Reads a password. It is split at single spaces and each word is compared with the list exactly
/// as written, hyphens included: the prefix rules of seed phrases do not apply, since the list has
/// both "yo-yo" and "yoyo". A word not in the list, such as "?", is a gap.
fn read(list: &EffList, text: &str) -> (Reading, Vec<Repair>) {
    let ranges = token_ranges(text);
    if ranges.len() != DRAWN_WORDS + 1 {
        return (Reading::NotThisShape, Vec::new());
    }
    // The positions in the list reveal the password: wiped when done.
    let found: Zeroizing<Vec<Option<usize>>> = Zeroizing::new(
        ranges
            .iter()
            .map(|range| list.index_of(&text[range.clone()]))
            .collect(),
    );
    let gaps: Vec<usize> = (0..ranges.len()).filter(|&i| found[i].is_none()).collect();
    let known: Zeroizing<Vec<usize>> =
        Zeroizing::new(found.iter().map(|index| index.unwrap_or(0)).collect());
    let repair_at = |position: usize| Repair {
        position: position + 1,
        word: list.word(restored_index(&known, position)),
        typed: ranges[position].clone(),
    };
    match gaps.as_slice() {
        [] if restored_index(&known, DRAWN_WORDS) == known[DRAWN_WORDS] => {
            (Reading::Fits, Vec::new())
        }
        [] => (
            Reading::Mismatch,
            (0..ranges.len()).map(repair_at).collect(),
        ),
        [gap] => (Reading::Restorable, vec![repair_at(*gap)]),
        _ => (Reading::NotThisShape, Vec::new()),
    }
}

/// The byte ranges of the words of `text` split at single spaces.
fn token_ranges(text: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = 0;
    for token in text.split(' ') {
        ranges.push(start..start + token.len());
        start += token.len() + 1;
    }
    ranges
}

/// The index at `position` that makes the six fit, the other five as given.
fn restored_index(indexes: &[usize], position: usize) -> usize {
    let mut drawn = Zeroizing::new([0usize; DRAWN_WORDS]);
    drawn.copy_from_slice(&indexes[..DRAWN_WORDS]);
    if position == DRAWN_WORDS {
        return weighted_index(&drawn);
    }
    // weight * d = check - (the weighted sum of the others): d is that times the weight's inverse.
    drawn[position] = 0;
    let wanted = (indexes[DRAWN_WORDS] + LIST_SIZE - weighted_index(&drawn)) % LIST_SIZE;
    wanted * inverse(WEIGHTS[position]) % LIST_SIZE
}

/// The inverse of `weight` modulo 7,776, which exists because the weight is coprime to it.
#[expect(
    clippy::expect_used,
    reason = "every weight is coprime to 7,776, so its inverse exists"
)]
fn inverse(weight: usize) -> usize {
    (1..LIST_SIZE)
        .find(|&candidate| weight * candidate % LIST_SIZE == 1)
        .expect("every weight is coprime to 7,776")
}

/// `text` with one word replaced, built at its final size and locked, so that no unwiped copy is
/// left behind.
fn repaired(text: &str, repair: &Repair) -> LockedText {
    let capacity = text.len() - repair.typed.len() + repair.word.len();
    let Ok(result) = LockedText::build::<Infallible>(capacity, |result| {
        result.push_str(&text[..repair.typed.start]);
        result.push_str(repair.word);
        result.push_str(&text[repair.typed.end..]);
        Ok(())
    });
    result
}

/// The profile's written form of a typed password, its words in small letters one space apart
/// with no space before or after, and what that changed; `None` when nothing changes. It is built
/// at its final size and locked, as the password itself is.
fn written_form(typed: &str) -> Option<(LockedText, Correction)> {
    let extra_spaces = typed.split(' ').any(str::is_empty);
    let capitals = typed.bytes().any(|byte| byte.is_ascii_uppercase());
    let correction = match (extra_spaces, capitals) {
        (false, false) => return None,
        (true, false) => Correction::ExtraSpaces,
        (false, true) => Correction::Capitals,
        (true, true) => Correction::SpacesAndCapitals,
    };
    // Never longer than typed: spaces are only removed, and ASCII letters keep their length.
    let Ok(text) = LockedText::build::<Infallible>(typed.len(), |text| {
        for (index, word) in typed.split(' ').filter(|word| !word.is_empty()).enumerate() {
            if index > 0 {
                text.push(' ');
            }
            text.extend(word.chars().map(|letter| letter.to_ascii_lowercase()));
        }
        Ok(())
    });
    Some((text, correction))
}

impl crate::ErrorIdentity for ReviewError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drawn(rolls: &str) -> [usize; DRAWN_WORDS] {
        let indexes: Vec<usize> = rolls
            .split(' ')
            .map(|roll| EffList::index_of_rolls(roll).unwrap())
            .collect();
        indexes.try_into().unwrap()
    }

    /// The password of five drawn word indexes and their check word.
    fn password(drawn: &[usize; DRAWN_WORDS]) -> String {
        let list = EffList::get();
        drawn
            .iter()
            .chain(std::iter::once(
                &PasswordReview::check_index(drawn).unwrap(),
            ))
            .map(|&index| list.word(index))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn the_public_vectors_are_reproduced() {
        for case in known_answers::VECTORS {
            let (rolls, check, expected) = (case.rolls, case.check_index, case.password);
            assert_eq!(
                PasswordReview::check_index(&drawn(rolls)),
                Ok(check),
                "{rolls}"
            );
            assert_eq!(password(&drawn(rolls)), expected);
            assert_eq!(PasswordReview::of(expected).reading(), Reading::Fits);
        }
    }

    #[test]
    fn an_outside_list_index_is_refused_without_overflow() {
        for indexes in [[7776, 0, 0, 0, 0], [0, 0, 0, 0, usize::MAX]] {
            let error = PasswordReview::check_index(&indexes).unwrap_err();
            assert_eq!(error, ReviewError::InvalidIndex);
            assert_eq!(error.code(), "INVALID_REQUEST");
            assert!(!error.to_string().contains(&usize::MAX.to_string()));
        }
    }

    #[test]
    fn check_indexes_match_literal_boundary_answers() {
        // The profile's weighted sum, with weights adding to 37; no runtime computation of
        // the expected answer (CORE-28).
        for (indexes, expected) in [([0; 5], 0), ([1, 2, 3, 4, 5], 141), ([7775; 5], 7739)] {
            assert_eq!(PasswordReview::check_index(&indexes), Ok(expected));
        }
    }

    /// "In the third row, an erased third word is recovered as chokehold."
    #[test]
    fn the_erased_third_word_of_the_third_vector_is_chokehold() {
        let (erased, position, word) = known_answers::ERASED;
        let review = PasswordReview::of(erased);
        assert_eq!(review.reading(), Reading::Restorable);
        let repair = &review.repairs()[0];
        assert_eq!((repair.position(), repair.word()), (position, word));
        assert_eq!(review.typed_word(repair), UNREADABLE);
        assert!(review.repairs_first());
    }

    #[test]
    fn one_missing_word_is_restored_at_any_place() {
        for case in known_answers::VECTORS {
            let expected = case.password;
            for position in 0..=DRAWN_WORDS {
                let mut words: Vec<&str> = expected.split(' ').collect();
                words[position] = "unreadable";
                let review = PasswordReview::of(&words.join(" "));
                assert_eq!(
                    review.reading(),
                    Reading::Restorable,
                    "{expected}, {position}"
                );
                assert!(
                    !review.repairs_first(),
                    "only a ? asks for the repair first"
                );
                let restored = review.apply(ReviewChoice::Repair(position + 1)).unwrap();
                assert_eq!(&*restored, expected);
            }
        }
    }

    #[test]
    fn one_wrong_word_leaves_six_repairs_with_the_right_one_among_them() {
        let expected = known_answers::VECTORS[0].password;
        let typed = expected.replace("abide", "zoom");
        let review = PasswordReview::of(&typed);
        assert_eq!(review.reading(), Reading::Mismatch);
        assert_eq!(review.repairs().len(), DRAWN_WORDS + 1);
        let right: Vec<usize> = review
            .repairs()
            .iter()
            .filter(|repair| {
                &*review
                    .apply(ReviewChoice::Repair(repair.position()))
                    .unwrap()
                    == expected
            })
            .map(Repair::position)
            .collect();
        assert_eq!(right, [4]);
        assert_eq!(review.typed_word(&review.repairs()[3]), "zoom");
        // Every one of the six makes the words fit.
        for repair in review.repairs() {
            let repaired = review
                .apply(ReviewChoice::Repair(repair.position()))
                .unwrap();
            assert_eq!(PasswordReview::of(&repaired).reading(), Reading::Fits);
        }
        assert_eq!(&*review.apply(ReviewChoice::AsTyped).unwrap(), typed);
    }

    #[test]
    fn the_debug_text_of_a_repair_gives_no_part_of_the_password() {
        let expected = known_answers::VECTORS[0].password;
        let reviews = [
            PasswordReview::of("jovial trailing ? pavilion cresting ninth"),
            PasswordReview::of(&expected.replace("abide", "zoom")),
        ];
        for review in &reviews {
            for repair in review.repairs() {
                let text = format!("{repair:?}");
                assert_eq!(
                    text,
                    format!("Repair {{ position: {}, .. }}", repair.position())
                );
                assert!(!text.contains(repair.word()), "{text}");
            }
        }
    }

    #[test]
    fn extra_spaces_and_capitals_give_the_written_form() {
        let review = PasswordReview::of(" jovial trailing ? pavilion  cresting ninth ");
        assert_eq!(review.correction(), Some(Correction::ExtraSpaces));
        assert_eq!(review.reading(), Reading::Restorable);
        // A repair of the written form carries the correction with it.
        assert_eq!(
            &*review.apply(ReviewChoice::Repair(3)).unwrap(),
            "jovial trailing chokehold pavilion cresting ninth"
        );
        assert!(!review.offers_correction());
        let review = PasswordReview::of("JOVIAL Trailing chokehold pavilion cresting ninth");
        assert_eq!(review.correction(), Some(Correction::Capitals));
        assert_eq!(review.reading(), Reading::Fits);
        assert!(review.offers_correction());
        assert!(review.repairs_first());
        assert_eq!(
            &*review.apply(ReviewChoice::Corrected).unwrap(),
            "jovial trailing chokehold pavilion cresting ninth"
        );
        let review = PasswordReview::of("  Jovial trailing chokehold pavilion cresting ninth");
        assert_eq!(review.correction(), Some(Correction::SpacesAndCapitals));
        assert_eq!(
            Correction::SpacesAndCapitals.text(),
            "spaces and capitals corrected"
        );
        // The written form already: nothing to correct.
        let review = PasswordReview::of("jovial trailing chokehold pavilion cresting ninth");
        assert_eq!(review.correction(), None);
    }

    #[test]
    fn a_typed_password_needs_its_rules_then_the_same_repetition() {
        let typed = "jovial trailing ? pavilion cresting ninth";
        assert!(matches!(
            Password::from_typed(typed, Some("jovial"), None),
            Err(crate::PasswordError::PasswordsDiffer)
        ));
        // The password's own rules come before the repetition.
        assert!(matches!(
            Password::from_typed("", Some("jovial"), None),
            Err(crate::PasswordError::EmptyPassword)
        ));
        assert_eq!(
            Password::from_typed(typed, Some(typed), None)
                .unwrap()
                .as_bytes(),
            typed.as_bytes()
        );
        assert_eq!(
            Password::from_typed(typed, Some(typed), Some(ReviewChoice::Repair(3)))
                .unwrap()
                .as_bytes(),
            b"jovial trailing chokehold pavilion cresting ninth"
        );
        assert_eq!(
            &*PasswordReview::choose(typed, Some(ReviewChoice::Repair(3))).unwrap(),
            "jovial trailing chokehold pavilion cresting ninth"
        );
    }

    #[test]
    fn choices_not_offered_are_refused() {
        let (erased, _, _) = known_answers::ERASED;
        let review = PasswordReview::of(erased);
        assert!(matches!(
            review.apply(ReviewChoice::Repair(2)),
            Err(ReviewError::NotOffered)
        ));
        assert!(matches!(
            review.apply(ReviewChoice::Corrected),
            Err(ReviewError::NotOffered)
        ));
    }

    #[test]
    fn other_passwords_are_left_alone() {
        for typed in [
            "correct horse battery staple",
            "abacus abdomen abdominal abide abiding",
            "abacus ? ? abide abiding aids",
            "Abacus abdomen abdominal abide abiding aids extra",
        ] {
            let review = PasswordReview::of(typed);
            assert_eq!(review.reading(), Reading::NotThisShape, "{typed}");
            assert_eq!(review.correction(), None, "{typed}");
            assert!(review.repairs().is_empty());
        }
        // Words count only as written: "yoyo" and "yo-yo" are different words of the list.
        assert_eq!(
            PasswordReview::of("drop-down t-shirt abacus yoyo felt-tip rubble").reading(),
            Reading::Mismatch
        );
    }
}
