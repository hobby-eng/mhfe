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
use crate::MhfeError;

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-passwords"
))]
pub(crate) mod known_answers;

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

/// The index of the check word for the indexes of the five drawn words:
/// (d1 + 5 d2 + 7 d3 + 11 d4 + 13 d5) mod 7776.
pub fn check_index(drawn: &[usize; DRAWN_WORDS]) -> usize {
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
    /// Each place allows exactly one repair, so there are six.
    Mismatch,
}

/// How the written form of a password differs from the text typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Correction {
    ExtraSpaces,
    Capitals,
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

/// One word of the reviewed password replaced so that the six fit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repair {
    position: usize,
    word: &'static str,
    /// Where the word as typed lies in the reviewed text.
    typed: Range<usize>,
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
    pub fn apply(&self, choice: ReviewChoice) -> Result<LockedText, MhfeError> {
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
                .ok_or(MhfeError::PasswordRepairNotOffered),
            ReviewChoice::Corrected => Err(MhfeError::PasswordRepairNotOffered),
        }
    }

    /// The text the reading is of.
    fn reviewed(&self) -> &str {
        self.written.as_ref().map_or(&*self.typed, |(form, _)| form)
    }
}

/// The password a person typed for a new container or wallet, after the review choice they made:
/// `repeat`, when given, must be exactly the same text, as both entries are compared before any
/// review; `choice` applies a correction or repair the review offered, and `None` keeps the text
/// as typed.
pub fn chosen_password(
    typed: &str,
    repeat: Option<&str>,
    choice: Option<ReviewChoice>,
) -> Result<LockedText, MhfeError> {
    if repeat.is_some_and(|repeat| repeat != typed) {
        return Err(MhfeError::PasswordsDiffer);
    }
    match choice {
        None | Some(ReviewChoice::AsTyped) => Ok(LockedText::copy_of(typed)),
        Some(choice) => PasswordReview::of(typed).apply(choice),
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
    let mut drawn: Zeroizing<[usize; DRAWN_WORDS]> = Zeroizing::new(
        indexes[..DRAWN_WORDS]
            .try_into()
            .expect("a password of the profile has five drawn words"),
    );
    if position == DRAWN_WORDS {
        return check_index(&drawn);
    }
    // weight * d = check - (the weighted sum of the others): d is that times the weight's inverse.
    drawn[position] = 0;
    let wanted = (indexes[DRAWN_WORDS] + LIST_SIZE - check_index(&drawn)) % LIST_SIZE;
    wanted * inverse(WEIGHTS[position]) % LIST_SIZE
}

/// The inverse of `weight` modulo 7,776, which exists because the weight is coprime to it.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eff::index_of_rolls;

    fn drawn(rolls: &str) -> [usize; DRAWN_WORDS] {
        let indexes: Vec<usize> = rolls
            .split(' ')
            .map(|roll| index_of_rolls(roll).unwrap())
            .collect();
        indexes.try_into().unwrap()
    }

    /// The password of five drawn word indexes and their check word.
    fn password(drawn: &[usize; DRAWN_WORDS]) -> String {
        let list = EffList::get();
        drawn
            .iter()
            .chain(std::iter::once(&check_index(drawn)))
            .map(|&index| list.word(index))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The public vectors of the specification.
    const VECTORS: [(&str, usize, &str); 4] = [
        (
            "11111 11112 11113 11114 11115",
            104,
            "abacus abdomen abdominal abide abiding aids",
        ),
        (
            "66666 66666 66666 66666 66666",
            7739,
            "zoom zoom zoom zoom zoom yelling",
        ),
        (
            "35214 62431 15543 44126 21365",
            4150,
            "jovial trailing chokehold pavilion cresting ninth",
        ),
        (
            "24255 61534 11111 66622 26522",
            5527,
            "drop-down t-shirt abacus yo-yo felt-tip rubble",
        ),
    ];

    #[test]
    fn the_public_vectors_are_reproduced() {
        for (rolls, check, expected) in VECTORS {
            assert_eq!(check_index(&drawn(rolls)), check, "{rolls}");
            assert_eq!(password(&drawn(rolls)), expected);
            assert_eq!(PasswordReview::of(expected).reading(), Reading::Fits);
        }
    }

    /// "In the third row, an erased third word is recovered as chokehold."
    #[test]
    fn the_erased_third_word_of_the_third_vector_is_chokehold() {
        let review = PasswordReview::of("jovial trailing ? pavilion cresting ninth");
        assert_eq!(review.reading(), Reading::Restorable);
        let repair = &review.repairs()[0];
        assert_eq!((repair.position(), repair.word()), (3, "chokehold"));
        assert_eq!(review.typed_word(repair), UNREADABLE);
        assert!(review.repairs_first());
    }

    #[test]
    fn one_missing_word_is_restored_at_any_place() {
        for (_, _, expected) in VECTORS {
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
        let (_, _, expected) = VECTORS[0];
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
    fn a_chosen_password_needs_the_same_repetition() {
        let typed = "jovial trailing ? pavilion cresting ninth";
        assert!(matches!(
            chosen_password(typed, Some("jovial"), None),
            Err(MhfeError::PasswordsDiffer)
        ));
        assert_eq!(&*chosen_password(typed, Some(typed), None).unwrap(), typed);
        assert_eq!(
            &*chosen_password(typed, None, Some(ReviewChoice::Repair(3))).unwrap(),
            "jovial trailing chokehold pavilion cresting ninth"
        );
    }

    #[test]
    fn choices_not_offered_are_refused() {
        let review = PasswordReview::of("jovial trailing ? pavilion cresting ninth");
        assert!(matches!(
            review.apply(ReviewChoice::Repair(2)),
            Err(MhfeError::PasswordRepairNotOffered)
        ));
        assert!(matches!(
            review.apply(ReviewChoice::Corrected),
            Err(MhfeError::PasswordRepairNotOffered)
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
