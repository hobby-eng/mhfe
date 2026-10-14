# Phrase frame probe (AUD-024, commit b6fca69)

Checks CORE-36 ("A result ... lists its facts as grey labels with their values, without boxes or
rules") on the phrase display of the command-line tool. `repair_frame_probe.py` drives
`mhfe repair` in a pseudo-terminal (TERM=xterm-256color, NO_COLOR=1) with public test data only:
the 12-word "abandon ... about" phrase with its last word typed as `?`, and its two repair words
`access adapt` (from `mhfe repair-words --stdin --count 2`). No Argon2 runs. It prints the
transcript (ESC shown as `<ESC>`) and every line of a box frame (`┌`, `│`, `└`) it finds.

Inputs: a debug build of `mhfe` at b6fca69.

Command from the repository root:

    CARGO_TARGET_DIR=/home/user/.../tmp/aud024/target cargo build --locked --bin mhfe
    python3 docs/audits/AUD-024-harnesses/verify-phrase-frame/repair_frame_probe.py \
      /home/user/.../tmp/aud024/target/debug/mhfe

Expected output at b6fca69: the check fails (exit 1) with "frame lines found: 10", the frame
drawn once around the repaired container in the repair question (container_repair.rs:447) and
once on the private screen (terminal.rs:477 through print_phrase, container_repair.rs:508). Exit 0
means no frame was drawn; exit 2 or a Python error is a probe fault.
