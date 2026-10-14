//! The private screen: secrets and the steps of a command on the terminal's alternate screen,
//! which never reach the main screen or its scrollback.

use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use super::{control, write_control, Input};
use crate::exit::Failure;
use crate::flow;
use crate::hidden_input;
use crate::style;

/// Switches to the terminal's alternate screen, clears it and moves to its top left (xterm
/// control sequences, also understood by tmux and most terminals).
const ENTER_ALTERNATE_SCREEN: &str = "\x1b[?1049h\x1b[2J\x1b[H";
/// Clears the screen and puts the cursor at its top left (VT100 "erase in display" and "home").
const CLEAR_SCREEN: &str = "\x1b[2J\x1b[H";
/// Clears the alternate screen, then returns to the main screen with its earlier content. The
/// clear comes first so that the words also vanish where the alternate screen is not supported,
/// such as GNU screen without `altscreen on`.
const LEAVE_ALTERNATE_SCREEN: &str = "\x1b[2J\x1b[H\x1b[?1049l";

/// Set while secret words are on the alternate screen, so that Ctrl+C can leave it first.
static PRIVATE_SCREEN_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether the tool writes on the alternate screen now, a private screen or the steps of a command.
pub(crate) fn on_alternate_screen() -> bool {
    PRIVATE_SCREEN_ACTIVE.load(Ordering::SeqCst)
}

/// Secrets on the terminal's alternate screen, as `less` shows a file: they never reach the main
/// screen or its scrollback, and dropping this clears them and returns to where the tool was. A
/// script, a pipe or a file gets none of this.
pub(crate) struct PrivateScreen {
    active: bool,
    /// A step of a command shown one step at a time (flow.rs), on the alternate screen it is
    /// already on: dropping it only clears the screen.
    step: bool,
}

impl PrivateScreen {
    /// A screen for typing secrets, which are shown there as they are typed. It needs the
    /// terminal on standard input and standard error only: the result may go to a file.
    pub(crate) fn enter(input: &Input, title: &str) -> Result<Self, Failure> {
        let screen = Self::enter_if(input, true)?;
        if screen.active {
            style::title(title);
            style::hint("Cleared when you are done; until then anyone who sees it can read it.");
        }
        Ok(screen)
    }

    /// A screen for showing a secret result, such as a recovered phrase, which goes to standard
    /// output: it is used only when standard output is the terminal too.
    pub(crate) fn enter_to_show(input: &Input) -> Result<Self, Failure> {
        Self::enter_if(input, output_on_screen())
    }

    fn enter_if(input: &Input, output_allows: bool) -> Result<Self, Failure> {
        control::require_healthy()?;
        // A command shown one step at a time is on the alternate screen throughout: a private
        // screen is a step of its own there, cleared again when it ends.
        if flow::is_active() {
            flow::step()?;
            return Ok(Self {
                active: true,
                step: true,
            });
        }
        // Within a private screen, another one adds nothing: the outer one stays, and is left
        // and cleared only when it ends, so that nothing reaches the main screen in between.
        if PRIVATE_SCREEN_ACTIVE.load(Ordering::SeqCst) {
            return Ok(Self {
                active: false,
                step: false,
            });
        }
        let active = output_allows && terminal_screen_possible(input);
        if active {
            // Written raw: anstream would drop control sequences when NO_COLOR is set.
            activate_screen(&PRIVATE_SCREEN_ACTIVE, write_control)?;
        }
        Ok(Self {
            active,
            step: false,
        })
    }

    /// Whether the secrets are on the alternate screen, which then waits for the person.
    pub(crate) fn is_active(&self) -> bool {
        self.active
    }

    /// Whether what is printed now stays private: this screen is active, or it lies within one
    /// that is.
    pub(crate) fn shows_privately(&self) -> bool {
        self.active || PRIVATE_SCREEN_ACTIVE.load(Ordering::SeqCst)
    }

    /// Clears the screen for what comes next, such as another password in its place.
    pub(crate) fn clear(&self) -> Result<(), Failure> {
        if self.active {
            write_control(CLEAR_SCREEN)?;
        }
        Ok(())
    }
}

/// Whether a person at a terminal can be shown a secret on a private screen: standard input,
/// output and error are the terminal, output and error the same one, and it can switch screens.
/// A command that must show a phrase only privately refuses otherwise, before anything secret is
/// asked (AUD-007-SEC001).
pub(crate) fn can_show_privately(input: &Input) -> bool {
    output_on_screen() && terminal_screen_possible(input)
}

/// The input of a command that shows a phrase only on a private screen: the terminal, or the
/// refusal `refused` where there can be none, before anything secret is asked (AUD-007-SEC001).
pub(crate) fn private_input(refused: &str) -> Result<Input, Failure> {
    let input = Input::terminal_only();
    if !can_show_privately(&input) {
        return Err(Failure::invalid_input(refused));
    }
    Ok(input)
}

/// Whether what goes to standard output appears on the terminal of standard error, on which the
/// private screen is switched and cleared: both are terminals, and the same one. Output sent to
/// another terminal counts as redirected (AUD-008-SEC004).
pub(crate) fn output_on_screen() -> bool {
    io::stdout().is_terminal()
        && io::stderr().is_terminal()
        && hidden_input::output_on_error_terminal()
}

fn terminal_screen_possible(input: &Input) -> bool {
    !input.is_script() && hidden_input::can_redraw()
}

/// Asks the person to write down what the private screen shows, and waits for Enter or Escape,
/// after which the screen is cleared: what it showed then leaves the terminal and its scrollback.
/// Every other key is ignored, so that a stray one cannot clear the screen too early.
pub(crate) fn wait_to_leave() -> Result<(), Failure> {
    wait_to_leave_saying("Write it down now: Enter or Escape clears this screen.")
}

/// [`wait_to_leave`] with another line above the wait, for a screen that needs no writing down.
pub(super) fn wait_to_leave_saying(line: &str) -> Result<(), Failure> {
    eprintln!();
    style::warn_here(line, "");
    hidden_input::with_keys(|next_key| loop {
        match next_key()? {
            hidden_input::Key::Enter | hidden_input::Key::Quit => return Ok(()),
            _ => continue,
        }
    })
}

impl Drop for PrivateScreen {
    fn drop(&mut self) {
        if self.step {
            // Drop cannot return an error. Controls remember an uncertain screen mode, so a
            // later private operation refuses it; cleanup still makes its bounded attempt.
            let _ = io::stdout().flush();
            let _ = write_control(CLEAR_SCREEN);
        } else if self.active {
            leave_private_screen();
        }
    }
}

/// Switches to the alternate screen for the steps of a command (flow.rs). False where they cannot
/// be shown privately, or within a screen that is already private.
pub(crate) fn enter_steps(input: &Input) -> Result<bool, Failure> {
    control::require_healthy()?;
    if PRIVATE_SCREEN_ACTIVE.load(Ordering::SeqCst) || !can_show_privately(input) {
        return Ok(false);
    }
    activate_screen(&PRIVATE_SCREEN_ACTIVE, write_control)?;
    Ok(true)
}

/// Returns from the steps of a command to the main screen, clearing what they showed.
pub(crate) fn leave_steps() {
    leave_private_screen();
}

/// Clears the screen for the next step of a command.
pub(crate) fn clear_screen() -> Result<(), Failure> {
    io::stdout().flush()?;
    write_control(CLEAR_SCREEN)
}

pub(super) fn leave_private_screen() {
    if PRIVATE_SCREEN_ACTIVE.swap(false, Ordering::SeqCst) {
        // Cancellation and Drop cannot return a cleanup error. A failed control records the
        // uncertain mode and prevents a later private operation from relying on this flag.
        let _ = io::stdout().flush();
        let _ = write_control(LEAVE_ALTERNATE_SCREEN);
    }
}

/// Set the active flag only after the full switch and clear have reached the terminal.
fn activate_screen(
    active: &AtomicBool,
    mut send: impl FnMut(&str) -> Result<(), Failure>,
) -> Result<(), Failure> {
    if let Err(error) = send(ENTER_ALTERNATE_SCREEN) {
        // An incomplete switch may have entered the alternate screen. Cleanup cannot replace
        // the original error and never has private content to erase at this point.
        let _ = send(LEAVE_ALTERNATE_SCREEN);
        return Err(error);
    }
    active.store(true, Ordering::SeqCst);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_screen_switch_never_marks_secrets_as_private() {
        let active = AtomicBool::new(false);
        let mut controls = Vec::new();
        let failed = activate_screen(&active, |sequence| {
            controls.push(sequence.to_owned());
            Err(Failure::internal("public synthetic write failure"))
        })
        .unwrap_err();
        assert_eq!(failed.message, "public synthetic write failure");
        assert!(!active.load(Ordering::SeqCst));
        assert_eq!(controls, [ENTER_ALTERNATE_SCREEN, LEAVE_ALTERNATE_SCREEN]);
    }

    #[test]
    fn the_private_flag_is_set_only_after_the_complete_switch() {
        let active = AtomicBool::new(false);
        activate_screen(&active, |sequence| {
            assert_eq!(sequence, ENTER_ALTERNATE_SCREEN);
            assert!(!active.load(Ordering::SeqCst));
            Ok(())
        })
        .unwrap();
        assert!(active.load(Ordering::SeqCst));
    }
}
