# verify-stdin-buffer-residue (audit AUD-024, commit b6fca69)

Checks whether a line that mhfe would read from standard input is left in the Rust standard
library's stdin buffer after the program wiped its own copy. The probe (`probe/src/main.rs`, std
only, Linux) reads one line in the two ways the command-line tool does, and in a control way:

- `bytes`: one byte at a time from `io::stdin().lock()`, as `src/bin/mhfe/hidden_input.rs`
  `edit_line` does for hidden and shown prompts (lines 100, 107, 491);
- `line`: `take(8192).read_line` on `io::stdin().lock()` into a String reserved at 8192, as
  `src/bin/mhfe/terminal.rs` `read_bounded_line` does for `--stdin` and visible prompts (line 444);
- `descriptor`: one byte at a time from file descriptor 0 (control, no std buffer).

It wipes its own copy with volatile writes, keeps it allocated, and scans the heap and anonymous
mappings through `/proc/self/mem` for the public test text `public test password` (given reversed,
so the probe holds no copy). It prints each copy's address and whether it lies inside std's buffer,
whose address it takes from `fill_buf` before reading. `run.py` runs it through a pipe (as with
`--stdin`) and through a pseudo-terminal in raw mode (as at a hidden prompt), the text pasted in
one write or typed one key at a time.

Inputs: none besides the public test text. No Argon2 runs.

Command, from the repository root:

    CARGO_TARGET_DIR=/home/user/.../tmp/aud024/target docs/audits/AUD-024-harnesses/verify-stdin-buffer-residue/run.sh

Expected output at b6fca69: one whole copy, inside std's buffer, for `bytes` and `line` through
the pipe and for `bytes` with the pasted line; none for `descriptor`, and none when typed one key
at a time; then `FAIL: ...` and exit 1. Once the tool reads standard input from the descriptor
into its own locked buffer, switching the probe's `bytes` and `line` modes to that reader must give
no copy (exit 0).
