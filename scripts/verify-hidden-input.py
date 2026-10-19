"""
Checks the terminal input of the mhfe tool in a pseudo-terminal (Linux
and macOS).

python3 scripts/verify-hidden-input.py [--full] [path/to/mhfe]

The default is target/debug/mhfe. --full adds the cases that run Argon2
at full size, 2 GiB at the default settings, which take minutes: one
encryption by `mhfe encrypt --stdin --repair-words 4`, which writes the
container and its card, and the three outcomes of `mhfe check --stdin`.
Without it they are left out, and the script names them: a push runs the
fast checks only (CI-04), and scripts/check.sh and CI on a release tag
pass --full.

At a terminal every step of a command has a screen of its own on the
terminal's alternate screen, and the main screen gets only the summary,
when the command ends. It drives `mhfe check --fingerprint --pim 0`,
which reads the container on a step of its own, taken at once, and then
the container password on another, and stops the tool before a
fingerprint is given, so no memory is reserved and Argon2 never runs;
the PIM given skips the question of the settings. Only the public
zero-12 test container is used.

It checks that - every control character in a password reaches the
password check and is refused, including the ones a terminal would
otherwise act on (Ctrl+S, Ctrl+Q, Ctrl+V, Ctrl+W, Ctrl+R, Ctrl+O,
Ctrl+\\, Ctrl+Z and Ctrl+D inside the line), and that a Unicode password
is accepted, also the longest one: 1024 characters U+1D400, 4096 bytes
that NFKD turns into 1024; - Backspace and Ctrl+U edit the line: a TAB
typed and then deleted leaves an accepted password; - the password is
shown as it is typed only on the alternate screen, which is cleared and
left before the summary, and none of its control characters is ever
written back; - Ctrl+C at the password ends the tool with exit code 130
and leaves the alternate screen; - the terminal settings are exactly the
original ones afterwards, after a normal answer and after Ctrl+C.

A password with a check word (MHFE-PASSWORD-CHECK-1) is repaired only on
the person's choice and before Argon2: a word typed as ? is restored as
the third public vector says, "chokehold", with the repair as the first
answer, also after a stray leading space, which the repair removes; a
wrong word gets the question with the password as typed first, and "Type
the password again" asks for it again. The summary records how the check
word came out and none of the words.

A command started directly runs in a network namespace with only
inactive loopback where the system allows user namespaces. Its summary
says "isolated network, no new sockets or file writes"; elsewhere it
says "no new sockets or file writes" for seccomp and Landlock alone.
Previously opened descriptors are not revoked by these restrictions.

It also drives the menu that `mhfe` shows when it starts without
arguments: the arrow keys and Enter choose an entry, its number chooses
it at once, other escape sequences (Ctrl+Up) and keys do nothing and are
not shown, q and a lone Escape quit with exit code 0 and Ctrl+C with
130, and the terminal settings are restored either way. The `mhfe
password` entry shows each password on one private screen, which it
clears for the next one on Enter and when Escape or q returns to the
menu; the help entry returns on Enter. Neither needs secret input.

`mhfe rekey` asks nothing about other wallets on the container: every
user gets a warning at the top of the container prompt that they do not
move to the new container and that the old one and its passwords are
kept until their funds are moved (the owner's decision of 2026-10-08, in
place of AUD-007-FUN002's question). No password is asked before it.

A rekey asks whether the wallet has a BIP39 passphrase
(multi-chain-wallet-tools AUD-022-API004) once, as soon as the kind of
confirmation is known, for every kind: the next screen after the
password when a 12-word phrase is confirmed by its built-in check, and
after the choice of an address, the fingerprint or showing the phrase
otherwise. It shows both answers and the link to the README section of
the command, and no reference or passphrase is asked before it. The
question has no default: no answer is marked and the hint says "Enter
selects once one is marked", Enter alone leaves the list as it is and
records nothing, an arrow marks an answer and the hint then says "Enter
selects", and a digit chooses at once. After "No BIP39 passphrase" an
address or the fingerprint is read without a passphrase prompt. After
"It has a BIP39 passphrase" it is followed by "BIP39 passphrase of the
wallet", without the "Enter if it has none" of `mhfe check`: an empty
one is refused with "Type the passphrase: you said the wallet has one."
and asked again, and a typed one is taken and never reaches the main
screen. The built-in check and showing the phrase ask for no passphrase
either way. On Linux these runs get an address space too small for the 2
GiB of memory level 0: whatever they ask comes before the memory is
reserved, and the reservation is refused before Argon2 runs, with exit
code 4. The summary then holds exactly one "Passphrase" record, the
answer, after the choice of the confirmation and before the reference.
Other systems do not enforce that limit, so there every run stops with
Escape at the question, after the arrow.

The same question at a terminal that cannot redraw a list (TERM=dumb),
after the hidden old password of a 12-word phrase, has numbered answers,
prompted as "Choice: " without a default: an empty line, or a number out
of range, gets "Type a number from 1 to 2." and the prompt again. On
Linux the capped run then takes 2 and stops at the memory reservation
with exit code 4; elsewhere Ctrl+C at the prompt ends the tool with exit
code 130.

Last, it answers the questions of `mhfe encrypt` up to the password, so
again without Argon2: its own settings, PIM 1 after a mistyped one; the
phrase, refused once for its checksum and then taken without a question;
the length question on a cleared screen, where ? explains both lengths
and the arrows and Enter keep 24 words; then at once the question about
repair words: `mhfe encrypt` asks nothing about a BIP39 passphrase, and
its list of what to keep names any passphrase of the wallet instead; no
repair words; Ctrl+C at the repeated password ends the tool. The summary
then records the settings, the phrase's length, the container's and the
repair choice, in the order they were asked, has no Passphrase record
and holds none of the questions. Escape at a list cancels with exit code
130. The phrase is the public zero-12 test phrase and the password a
synthetic one, which never reaches the main screen. `mhfe encrypt
--help` lists no BIP39 passphrase among what it asks for. A script,
`mhfe encrypt --stdin`, is not asked about the passphrase either: it
gives the phrase and two passwords that differ, which end the tool with
exit code 2 before Argon2. A terminal that cannot redraw a list
(TERM=dumb) gets the hidden password of `mhfe encrypt --pim 0` right
after the hidden phrase, with no question between them, and Ctrl+C there
ends the tool. The phrase is never shown there. The Keep line itself
appears only after the encryption's Argon2 at 2 GiB, which this script
runs only with --full and never at a terminal; its wording is checked by
the unit tests of src/bin/mhfe/encrypt.rs.

Finally it checks that a phrase the person did not ask to export is
shown only on a private screen (AUD-007-SEC001): `mhfe new` and `mhfe
wallets` refuse to start, before anything is asked and with nothing on
standard output, when standard output goes to a pipe or to a second
terminal (AUD-008-SEC004) or TERM is dumb, while `mhfe new` at a
terminal goes on to its first question; and `mhfe rekey` offers to show
the phrase for the owner's comparison only when standard output is the
terminal. Neither gets as far as Argon2.

`mhfe new` asks whether the new phrase gets a wallet check with nothing
marked either (AUD-010): after the passphrase typed twice, an Enter
typed ahead with the repeated passphrase and an Enter at the list do
nothing and record nothing, the hint offers "? explains both" on its
first line and says "Enter selects once one is marked · Esc cancels" on
its second, ? shows what each answer gives and costs and leaves none
marked, ↓ marks "No check" and the hint then fits one line, and Escape
cancels with exit code 130 before the question about repair words. The
passphrase, a synthetic one, never reaches the main screen.

`mhfe check` offers "The phrase + passphrase check" only with a BIP39
passphrase, as the library and the browser package do (AUD-010): after
the public zero-12 container, a password and the choice, it asks "BIP39
passphrase of the wallet" without "Enter if it has none", refuses an
empty one with "Type the passphrase: the phrase + passphrase check needs
one." and asks again, and takes BIP39's public test passphrase; on Linux
the capped run then stops at the memory reservation, with exit code 4
and "Passphrase typed" in the summary.

What a person reads without a terminal and in a script follows the
tool's style (AUD-010). A usage
error, such as an unknown option, a missing argument or two that cannot
go together, is one
"✗ Error:" line, bold red in colour, followed by clap's tip, the usage
and its pointer to --help,
with exit code 2, nothing on standard output and no clap "error:";
--help and --version still
print to standard output with exit code 0. The help of the tool and of
every command, -h and
--help, fits 80 columns and has an "Examples:" section. A long error,
the one for a phrase whose
checksum fails in `mhfe encrypt --stdin`, is wrapped to 78 columns under
its mark. Without a
terminal, `mhfe password --dice` and a piped `mhfe rekey` say to run the
command in a terminal and
name no --stdin, which they do not have, while `mhfe encrypt` names it.
`mhfe check --stdin
--address` without --coin compares with a Bitcoin address, as in v0.5.0,
and says so: its summary
records "Coin       Bitcoin, as no --coin was given", and the public
Ethereum address of the
zero-12 phrase is refused with exit code 2 by an error that names
Bitcoin and --coin. On Linux the
capped run with the phrase's public Bitcoin address, and the one with
--coin ethereum and its
Ethereum address, which records no such line, stop at the memory
reservation with exit code 4.

Every command that handles a secret, and the menu, first compares every
part of the program with its known answers; when they pass, nothing
shows: `mhfe encrypt` writes its first step first and the menu its
title. `mhfe self-test` runs these checks and the slower ones, up to
Argon2 at 256 MiB, never the 2 GiB of the published vectors. At a
terminal its report lists every part with its mark of a pass, in mhfe's
colours, names each part while it is tested and erases that line, and
ends with ✓ and exit code 0. With NO_COLOR, and with its output in a
pipe, the report holds no colour codes. The menu's self-test entry asks
"Which test?" and offers both tests; Escape returns to the menu, and the
first runs the same report. Copies of the program with one bit flipped
in a known answer of the checks at start, a repair card and a check-word
vector, stop `mhfe encrypt` before it asks anything, and the menu before
it is shown, with "✗ Error: Self-test at start failed", the part and
what differed, and exit code 1; their self-test names the part too. The
copies are made in a temporary folder (TMPDIR), signed again on macOS,
and deleted afterwards.
"""

import sys

# Deliberate copy in the four checker entry points: refuse before any
# optional dependency or test module loads. verify-python-checks.mjs
# checks
# their identical refusal under -O, -OO and PYTHONOPTIMIZE.
if sys.flags.optimize:
    sys.exit(
        "Python optimization disables assertions; run this checker "
        "without -O or PYTHONOPTIMIZE."
    )

# The cases, one module for each area, in the package next to this
# script: Python puts the
# folder of the script it runs first on the import path.
from terminal_suite.constants import FULL
from terminal_suite.address_options import (
    explicit_address_options_skip_questions_and_refuse_misplaced_options,
)
from terminal_suite.line_retry import (
    refused_lines_start_again_without_control_characters,
    public_input_refusals_retry_before_any_recovery,
)
from terminal_suite.spelling import supported_typographic_spellings_are_normalized
from terminal_suite.full_size import FULL_SIZE_CHECKS
from terminal_suite.new_passphrase import (
    new_wallet_passphrases_are_bounded_before_drawing,
)
from terminal_suite.menus import (
    a_lone_escape_quits_the_menu_and_restores_the_terminal,
    ctrl_c_ends_the_menu_with_exit_code_130_and_restores_the_terminal,
    a_dumb_terminal_shows_no_control_sequences_or_hints,
    encryption_lists_show_defaults_and_keep_the_phrase_private,
    a_dumb_terminal_numbers_encryption_choices_and_hides_the_phrase,
    menu_passwords_regenerate_and_clear_their_private_screens,
    a_new_wallet_requires_an_explicit_wallet_check_answer,
    a_new_wallet_asks_chosen_words_and_retries_conflicts,
    private_results_refuse_redirected_or_unusable_terminals,
    quit_keys_leave_the_private_screen,
    typed_ahead_keys_answer_no_later_question,
)
from terminal_suite.option_paths import (
    scan_gap_options_refuse_invalid_values_and_skip_the_gap_question,
    explicit_check_paths_are_used_and_misplaced_paths_are_refused,
    a_check_word_password_has_the_librarys_check_word,
    explicit_repair_options_ask_for_the_card_before_the_password,
    passphrase_repair_password_and_memory_options_reach_their_preflights,
    test_tool_options_refuse_bad_selections_before_any_argon2_work,
)
from terminal_suite.options import (
    given_options_skip_their_corresponding_questions,
    script_encryption_asks_no_passphrase_and_refuses_different_passwords,
    an_invalid_never_use_word_is_refused_before_any_question,
    password_sizes_outside_the_library_limits_are_refused,
    rekey_refuses_invalid_new_settings_before_any_question,
    script_messages_wrap_with_their_commands_input_names,
    unwritable_standard_error_refuses_a_successful_result,
    unwritable_standard_output_refuses_a_successful_result,
    usage_errors_hide_secrets_and_help_keeps_terminal_colours,
)
from terminal_suite.passwords import (
    a_mistyped_password_is_repaired_only_after_confirmation,
    secret_commands_have_an_empty_network_namespace_when_supported,
    made_passwords_are_copied_back_before_they_are_used,
    password_input_hides_keys_and_restores_the_terminal,
    public_word_hints_complete_and_erase_typed_words,
)
from terminal_suite.recovery import (
    length_detection_requests_a_reference_when_checks_do_not_identify_it,
    rekey_asks_about_the_wallet_passphrase_before_recovery,
    a_dumb_terminal_asks_rekey_choices_without_a_default,
    rekey_warns_that_other_wallets_remain_in_the_old_container,
    a_wallet_check_requires_a_nonempty_passphrase,
)
from terminal_suite.repair import (
    a_repair_card_restores_the_container_and_reports_changes,
    missing_word_search_states_the_cost_and_requires_confirmation,
    the_repair_command_restores_and_confirms_a_container,
    a_search_records_the_reference_as_soon_as_it_is_read,
)
from terminal_suite.self_test import (
    damaged_known_answers_stop_commands_before_any_secret_input,
    startup_checks_finish_without_progress_output,
    self_test_reports_every_part_and_restores_the_terminal,
)
from terminal_suite.serve import fast_mode_verifies_the_page_and_reports_its_address


def main():
    # Each result is shown at once, so that a CI log shows how far the
    # checks came.
    sys.stdout.reconfigure(line_buffering=True)
    password_input_hides_keys_and_restores_the_terminal()
    a_mistyped_password_is_repaired_only_after_confirmation()
    public_word_hints_complete_and_erase_typed_words()
    supported_typographic_spellings_are_normalized()
    explicit_address_options_skip_questions_and_refuse_misplaced_options()
    refused_lines_start_again_without_control_characters()
    public_input_refusals_retry_before_any_recovery()
    secret_commands_have_an_empty_network_namespace_when_supported()
    menu_passwords_regenerate_and_clear_their_private_screens()
    a_lone_escape_quits_the_menu_and_restores_the_terminal()
    ctrl_c_ends_the_menu_with_exit_code_130_and_restores_the_terminal()
    rekey_warns_that_other_wallets_remain_in_the_old_container()
    rekey_asks_about_the_wallet_passphrase_before_recovery()
    encryption_lists_show_defaults_and_keep_the_phrase_private()
    script_encryption_asks_no_passphrase_and_refuses_different_passwords()
    a_dumb_terminal_numbers_encryption_choices_and_hides_the_phrase()
    made_passwords_are_copied_back_before_they_are_used()
    a_dumb_terminal_asks_rekey_choices_without_a_default()
    private_results_refuse_redirected_or_unusable_terminals()
    a_new_wallet_requires_an_explicit_wallet_check_answer()
    new_wallet_passphrases_are_bounded_before_drawing()
    a_new_wallet_asks_chosen_words_and_retries_conflicts()
    an_invalid_never_use_word_is_refused_before_any_question()
    quit_keys_leave_the_private_screen()
    a_wallet_check_requires_a_nonempty_passphrase()
    rekey_refuses_invalid_new_settings_before_any_question()
    a_dumb_terminal_shows_no_control_sequences_or_hints()
    typed_ahead_keys_answer_no_later_question()
    given_options_skip_their_corresponding_questions()
    scan_gap_options_refuse_invalid_values_and_skip_the_gap_question()
    explicit_check_paths_are_used_and_misplaced_paths_are_refused()
    a_check_word_password_has_the_librarys_check_word()
    explicit_repair_options_ask_for_the_card_before_the_password()
    passphrase_repair_password_and_memory_options_reach_their_preflights()
    test_tool_options_refuse_bad_selections_before_any_argon2_work()
    fast_mode_verifies_the_page_and_reports_its_address()
    a_repair_card_restores_the_container_and_reports_changes()
    the_repair_command_restores_and_confirms_a_container()
    unwritable_standard_output_refuses_a_successful_result()
    unwritable_standard_error_refuses_a_successful_result()
    length_detection_requests_a_reference_when_checks_do_not_identify_it()
    a_search_records_the_reference_as_soon_as_it_is_read()
    missing_word_search_states_the_cost_and_requires_confirmation()
    password_sizes_outside_the_library_limits_are_refused()
    usage_errors_hide_secrets_and_help_keeps_terminal_colours()
    script_messages_wrap_with_their_commands_input_names()
    startup_checks_finish_without_progress_output()
    self_test_reports_every_part_and_restores_the_terminal()
    damaged_known_answers_stop_commands_before_any_secret_input()
    if FULL:
        for check in FULL_SIZE_CHECKS.values():
            check()
    else:
        print("left out without --full, as they run Argon2 at 2 GiB: "
              f"{'; '.join(FULL_SIZE_CHECKS)}")


if __name__ == "__main__":
    main()
