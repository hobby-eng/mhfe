# TERM=dumb private-screen probe (AUD-024)

Audit AUD-024, at commit b6fca69 (branch aud023-remediation). Kept by the verifier of the candidate
finding "Where no private screen can open (TERM=dumb), mhfe password, decrypt and encrypt print the
new password, the recovered phrase and the new container on the main screen".

## What it checks

In a pseudo-terminal (Linux or macOS, Python 3.9 or newer, standard library only):

- A. `mhfe password` with `TERM=dumb`: whether the five-word password is written, whether
  `ESC[?1049h` (the switch to the alternate screen) is written, and whether the tool waits for a key
  before it exits.
- B. The same with `TERM=xterm-256color`, the control case: the password appears only after
  `ESC[?1049h`, the tool waits, and after Enter it writes `ESC[?1049l` without repeating the
  password.
- C. `mhfe repair-words --count 4` with the public 24-word container "abandon ... art", at both
  values of TERM. It shows whether `PrivateScreen::enter_to_show`, the call that `decrypt` makes
  for the recovered phrase (src/bin/mhfe/decrypt.rs:212), opens the alternate screen.

No secret of anyone is used, no Argon2 round runs and no memory is reserved. The generated passwords
are random throwaway output.

## Inputs

The path of an mhfe binary built from the commit, debug or release.

## Command (from the repository root)

```sh
python3 docs/audits/AUD-024-harnesses/verify-dumb-private-screen/probe.py <path to mhfe>
```

## Expected output

At b6fca69 the probe exits 1, because case A shows the password on the main screen. The last line
is:

```text
RESULT: TERM=dumb shows the password on the main screen without a wait: True; control TERM=xterm-256color uses the alternate screen and waits: True
```

Case C prints `ESC[?1049h written: False` and the repair card on the main screen at TERM=dumb, and
`ESC[?1049h written: True` with a wait at TERM=xterm-256color. Once the defect is fixed, by refusing
or by asking before a secret is shown at a terminal without a private screen, case A no longer
shows the password without a wait, and the probe exits 0. The probe then needs updating to the
chosen behaviour, for example by checking the refusal text.
