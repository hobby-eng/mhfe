# AUD-008 CLI interface probes

`ui-terminal-probe.py` reviews CLI help, color handling, menu redraw and return paths, and
private-screen routing. It belongs to AUD-008 at commit
`b6993bb1c11834a01847d1812b31a24145ab1f18` plus the captured dirty-tree snapshot. It does not
edit product code, run Argon2, or generate a wallet.

Run from the MHFE repository root with Python 3 on Linux and a freshly built native binary:

```sh
python3 docs/audits/AUD-008-harnesses/ui-terminal-probe.py target/release/mhfe
```

The sole phrase/container input is the public fixture
`tests/fixtures/suite3-vectors/zero-12.json`. The deterministic repair output is public test
data. The harness needs POSIX pseudo-terminals, `fcntl`, and `termios`; it has no third-party
Python dependency. It creates PTYs rather than opening a terminal application or browser.

It prints one JSON result per assertion and retains transcripts and a source manifest in
`docs/audits/AUD-008-evidence/ui-terminal-probe.json` (local only). A successful result exits
zero; any failed assertion exits nonzero. The reviewed snapshot exits 1 with 29 assertions
passing and four failing assertions representing two root causes: stale narrow-menu rows
and private output routed to a different terminal from its screen-control sequences.

The menu text grids are derived from actual PTY output using a small CR/LF, delayed-wrap,
cursor-up and erase-display accounting model. They are not screenshots or proof of all
terminal emulators. Widths are set to 80, 60 and 40 columns before child startup. Tall PTYs
isolate wrapping from scrolling; short terminal heights and resize while waiting are not
covered. The 80-column control has one visible selection marker; narrow cases have two.

`CLICOLOR_FORCE=1` on a pipe is an explicit override diagnostic. Default and `NO_COLOR` pipe
cases must remain plain. Private-screen control sequences intentionally remain functional
with `NO_COLOR`; color escapes and cursor-control escapes have separate purposes.

To retain a bounded command ledger without overwriting another command record:

```sh
python3 docs/audits/AUD-008-harnesses/record-command.py \
  --label ui-terminal-final --timeout 60 -- \
  python3 docs/audits/AUD-008-harnesses/ui-terminal-probe.py target/release/mhfe
```

Use a new ledger label on a later rerun. The first run's command record and
`ui-terminal-original-harness-failure.json` remain local evidence: that harness closed a
child immediately after typing Escape/q, so its cleanup Ctrl+C raced the intended normal
exit. The corrected harness waits for expected natural exits, while deliberate cancellation
still sends Ctrl+C. Those original exit-code failures are harness errors, not product bugs.

This contribution reuses the existing QA unchanged hidden-input gate under
`TERM=xterm-256color` for additional public password-edit, fallback, help and cancellation
coverage. It does not rerun or add those assertions to its independent count. Native
Windows/macOS, physical-terminal visual inspection, screen readers, and GUI/QR/PDF behavior
are not established here; MHFE has no shipped graphical application or QR/PDF interface.
