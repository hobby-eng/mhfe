#![allow(dead_code)]
#[path = "../../../src/bin/mhfe/choice.rs"]
mod choice;
#[path = "../../../src/bin/mhfe/exit.rs"]
mod exit;
#[path = "../../../src/bin/mhfe/hidden_input.rs"]
mod hidden_input;
#[path = "../../../src/bin/mhfe/style.rs"]
mod style;
#[path = "../../../src/bin/mhfe/terminal.rs"]
mod terminal;
fn main() {
    let input = terminal::Input::new(false);
    let screen = terminal::PrivateScreen::enter_to_show(&input);
    eprintln!("AUDIT_PRIVATE_SCREEN_ACTIVE={}", screen.is_active());
    terminal::print_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        &input,
    );
}
