//! What the terminal cases of every system type and look for: the keys as a terminal sends them,
//! the prompts and answers of the tool, its exit code on a cancel and the menu's entries. The Unix
//! cases (terminal.rs) and the Windows ones (terminal_windows.rs) both take them from here.

/// The exit code of the tool when the person cancels (src/bin/mhfe/exit.rs).
pub(crate) const CANCELLED: u8 = 130;
/// What the tool prints next after a password: a refused one is asked again ("Please type it
/// again"), an accepted one leads to the wallet's BIP39 passphrase.
pub(crate) const REFUSED: &str = "again";
pub(crate) const ACCEPTED: &str = "passphrase of the wallet";
pub(crate) const CTRL_U: &str = "\x15";
pub(crate) const CTRL_C: &str = "\x03";
/// The keys of the menu, as a terminal sends them. Ctrl+Up carries a 5, which must not choose
/// entry 5.
pub(crate) const UP: &str = "\x1b[A";
pub(crate) const DOWN: &str = "\x1b[B";
pub(crate) const ENTER: &str = "\r";
pub(crate) const CTRL_UP: &str = "\x1b[1;5A";
pub(crate) const ESCAPE: &str = "\x1b";
/// The prompts are matched whole: the "Esc quits" at the end of the first must not pass for the
/// menu.
pub(crate) const MENU_SHOWN: &str = "Esc quits";
pub(crate) const BACK_TO_MENU: &str = "Press Enter to return to the menu (Esc quits).";
/// The question that `mhfe password` and the menu's password entry ask after a password, and the
/// question of the entry before it.
pub(crate) const PASSWORD_AGAIN: &str =
    "Press Enter for another password (Esc returns to the menu).";
pub(crate) const PASSWORD_KIND: &str = "What kind of password?";
/// The first question of `mhfe encrypt`.
pub(crate) const SETTINGS_QUESTION: &str = "Which settings should protect the phrase?";
/// The menu entries of `mhfe encrypt` and `mhfe password` when no browser tool lies next to the
/// program.
pub(crate) const ENCRYPT_ENTRY: u8 = 2;
pub(crate) const PASSWORD_ENTRY: u8 = 7;
/// The entry that shows the help, two below the password entry with mhfe self-test between: the
/// ninth, reached with the arrows from the password entry.
pub(crate) const HELP_FROM_PASSWORD: usize = 2;
/// A synthetic password.
pub(crate) const SECRET: &str = "synthetic";
