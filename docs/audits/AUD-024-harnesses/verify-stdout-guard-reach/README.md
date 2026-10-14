# verify-stdout-guard-reach

Audit AUD-024, commit b6fca69. Verifier harness for the candidate finding that the regression
test of AUD-023-FUN001, `every_result_is_written_through_one_function`
(src/bin/mhfe/main.rs:409-442), does not see writes to standard output that bypass `style::out`.

What it checks: it exports the commit with `git archive` into a scratch folder and adds, one at a
time, a write to standard output outside `style::out`, runs the guard test, and restores the file:

1. `println!` in `choice::draw_entries` (choice.rs, after the `#[cfg(test)]` item at :300);
2. `println!` in `style::error_lines` (style.rs, after the `#[cfg(test)]` item at :330);
3. `std::io::Write::write_all` on `std::io::stdout()` in `decrypt::print_result` (decrypt.rs,
   a file the guard reads whole);
4. control: `println!` in `menu::start` (menu.rs, before its only `#[cfg(test)]`).

Inputs: the commit (default b6fca69), a scratch folder, and `CARGO_TARGET_DIR`. No Argon2 runs;
it only compiles the `mhfe` test binary and runs one source-scanning test.

Command, from the repository root:

    CARGO_TARGET_DIR=/home/user/Documents/bip_tools/tmp/aud024/target \
      docs/audits/AUD-024-harnesses/verify-stdout-guard-reach/guard_reach.sh \
      /home/user/Documents/bip_tools/tmp/aud024/verify-stdout-guard-reach b6fca69

Expected output at b6fca69 (exit 1, the defect is present):

    MISSED: println! in choice.rs draw_entries, ... (the guard test passes)
    MISSED: println! in style.rs error_lines, ... (the guard test passes)
    MISSED: write_all on io::stdout() in decrypt.rs print_result, ... (the guard test passes)
    caught: control: println! in menu.rs start loop, ...
    mutations the guard missed: 3

After a fix it prints `caught:` on all four lines and `mutations the guard missed: 0`, exit 0.
Exit 2 means a mutation could not be applied or the build failed.
