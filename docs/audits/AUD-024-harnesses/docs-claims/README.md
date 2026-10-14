# AUD-024 harnesses: docs-claims

Harnesses of audit AUD-024 (documentation against behaviour), written at commit `b6fca69`
(`b6fca69238344dd2525b06270ee6ff3b055e68c1`). Each exits non-zero when its check fails. Run them
from the repository root.

| Harness | What it checks | Command | Expected output at b6fca69 |
| --- | --- | --- | --- |
| `check_links.py` | Every Markdown link of README.md, SECURITY.md, THIRD_PARTY_NOTICES.md, AGENTS.md, docs/API.md, docs/BROWSER-PACKAGE.md, docs/DEVELOPMENT.md, docs/RELEASING.md, docs/measurements/README.md, docs/releases/*.md and vendor/*.md: relative paths exist, anchors name a heading (GitHub's anchor rule), and links to github.com/hobby-eng/mhfe (blob/main, tree/main, #anchor) and github.com/hobby-eng/mhfe-spec#anchor resolve in the working tree and in ../mhfe_spec/README.md. | `python3 docs/audits/AUD-024-harnesses/docs-claims/check_links.py` | `232 links checked in 16 documents, 0 failed`, exit 0 |
| `check_reference_options.sh` | `mhfe check --coin` and `--path`, documented "With --address", are refused beside `--fingerprint` or `--words N` instead of ignored. Input: a one-word container on standard input, so nothing reaches Argon2. | `docs/audits/AUD-024-harnesses/docs-claims/check_reference_options.sh <path to a debug or release mhfe>` | four `ACCEPTED (defect)` lines, each ending at the one-word container refusal, then the control refused by clap; exit 1 |
| `fast_mode_page_name.sh` | A checksum line in the documented sha256sum format is served or refused for its real reason by both launchers (`mhfe serve` and `packaging/mhfe-fast-mode.py`). Inputs: generated pages `tool.htm` and `Tool.HTML` with their checksum files in a temporary folder. | `docs/audits/AUD-024-harnesses/docs-claims/fast_mode_page_name.sh <path to mhfe>` | four `FORMAT MESSAGE for a well-formed line (defect)` lines; exit 1 |

Inputs are public: the BIP39 word "abandon" and generated one-line HTML pages. No harness runs
Argon2 at full cost, and the launchers refuse before they listen on a port at b6fca69.
