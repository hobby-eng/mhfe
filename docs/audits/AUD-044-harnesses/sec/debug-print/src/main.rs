//! Prints what `{:?}` shows of `check_word::Repair`, of `word_hints::Hint` and of
//! `word_hints::Completion`, for a password of the check-word shape and a typed word.
use mhfe::check_word::PasswordReview;
use mhfe::word_hints::WordList;

fn main() {
    // Public test words of the EFF list; the sixth is no check word of the other five.
    let review = PasswordReview::of("zookeeper zoologist zoning zombie zodiac zipfile");
    println!("Repair: {:?}", review.repairs().first());
    println!("Hint: {:?}", WordList::Bip39.hint("hams"));
    println!("Completion: {:?}", WordList::Bip39.completion("hams"));
}
