//! Public raw phrase boundary probe, without an Argon2 engine or real wallet data.
use mhfe::{input_text::InputText, ContainerFacts, OriginalFacts, Phrase};
const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
fn accepted(text: &str) -> [bool; 3] {
    [
        Phrase::read(text).is_ok(),
        OriginalFacts::read(text).is_ok(),
        ContainerFacts::read(text).is_ok(),
    ]
}
fn main() {
    assert_eq!(accepted(WORDS), [true; 3]);
    let mut unexpected = 0;
    for internal in [false, true] {
        for bytes in [InputText::MAX_BYTES, InputText::MAX_BYTES + 1] {
            let padding = " ".repeat(bytes - WORDS.len());
            let text = if internal {
                let (first, rest) = WORDS.split_once(' ').unwrap();
                format!("{first}{padding} {rest}")
            } else {
                format!("{padding}{WORDS}")
            };
            assert_eq!(text.len(), bytes);
            let wanted = bytes <= InputText::MAX_BYTES;
            assert_eq!(InputText::read(&text).is_ok(), wanted);
            let actual = accepted(&text);
            println!("rawBytes={bytes} internalWhitespace={internal} accepted={actual:?} expected={wanted}");
            unexpected += usize::from(actual != [wanted; 3]);
        }
    }
    assert_eq!(
        unexpected, 0,
        "raw phrase readers must enforce the explicit input byte domain"
    );
}
