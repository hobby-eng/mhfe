"""Mutation probe for AUD-024 (commit b6fca69): does any test keep the Python fast-mode launcher's
copied values and messages equal to src/bin/mhfe/serve.rs and exit.rs?

Each mutation changes ONE copy in a scratch tree (serve.rs, exit.rs or the Python launcher alone),
then runs scripts/verify-fast-mode-script.py there. "PASSED" means no test noticed the drift.
Controls (marked CONTROL) change a copy the tests do read and must FAIL.
Exits 1 when a mutation of a copied value or message passes, or when a control does not fail.
Usage: python3 mutate.py <mhfe repository root> [scratch folder, the system temporary folder by default]
"""
import os, shutil, subprocess, sys, tempfile

ROOT = os.path.abspath(sys.argv[1])
SCRATCH = sys.argv[2] if len(sys.argv) > 2 else None
FILES = ["packaging/mhfe-fast-mode.py", "scripts/verify-fast-mode-script.py",
         "src/bin/mhfe/serve.rs", "src/bin/mhfe/style.rs", "src/bin/mhfe/hidden_input.rs",
         "src/bin/mhfe/exit.rs", "Cargo.lock"]
S, P, E = "src/bin/mhfe/serve.rs", "packaging/mhfe-fast-mode.py", "src/bin/mhfe/exit.rs"
MUTATIONS = [
    # (name, file, old, new, is_control)
    ("rs-refusal-no-readable", S, '"There is no readable {CHECKSUM_FILE}', '"There is no usable {CHECKSUM_FILE}', False),
    ("rs-refusal-names", S, '"{CHECKSUM_FILE} names {listed_name}, not {}; nothing', '"{CHECKSUM_FILE} lists {listed_name}, not {}; nothing', False),
    ("rs-refusal-cannot-read", S, '"Cannot read {}: {error}; nothing was served."', '"Could not read {}: {error}; nothing was served."', False),
    ("rs-refusal-sha256", S, 'The page has \\\n             changed or is not the one released', 'The page was \\\n             changed or is not the one released', False),
    ("rs-sha256-verified", S, '"SHA-256 of {} verified"', '"SHA-256 of {} checked"', False),
    ("rs-open-line", S, '"Open {shown} in your browser."', '"Go to {shown} in your browser."', False),
    ("rs-opened-line", S, '"Opened {shown}; if no browser shows it, open it yourself."', '"Opened {shown}; if nothing appears, open it yourself."', False),
    ("rs-running-line", S, '"Fast mode is running."', '"Fast mode is serving."', False),
    ("rs-close-line", S, '"Close this window or press Ctrl+C to stop."', '"Press Ctrl+C to stop."', False),
    ("rs-title", S, 'const TITLE: &str = "Fast mode";', 'const TITLE: &str = "Fast browser mode";', False),
    ("rs-sha256-hex-digits", S, 'const SHA256_HEX_DIGITS: usize = 64;', 'const SHA256_HEX_DIGITS: usize = 63;', False),
    ("rs-exit-invalid-input", E, 'pub const INVALID_INPUT: i32 = 2;', 'pub const INVALID_INPUT: i32 = 9;', False),
    ("rs-exit-internal-error", E, 'pub const INTERNAL_ERROR: i32 = 1;', 'pub const INTERNAL_ERROR: i32 = 7;', False),
    ("py-refusal-sha256", P, 'The page has changed or is not the one "', 'The page was altered or is not the one "', False),
    ("py-open-line", P, '"Open {} in your browser."', '"Visit {} in your browser."', False),
    ("py-title", P, 'TITLE = "Fast mode"', 'TITLE = "Quick mode"', False),
    ("CONTROL-rs-malformed", S, 'must hold exactly one line: the page\'s SHA-256, two spaces', 'must hold exactly one line: the page\'s SHA-256, 2 spaces', True),
    ("CONTROL-rs-max-connections", S, 'const MAX_CONNECTIONS: usize = 16;', 'const MAX_CONNECTIONS: usize = 17;', True),
    ("CONTROL-rs-security-header", S, '("Referrer-Policy", "no-referrer")', '("Referrer-Policy", "same-origin")', True),
    ("CONTROL-rs-checksum-file", S, 'pub const CHECKSUM_FILE: &str = "mhfe-fast-mode.sha256";', 'pub const CHECKSUM_FILE: &str = "mhfe-serve.sha256";', True),
]

def tree():
    folder = tempfile.mkdtemp(prefix="mutation-", dir=SCRATCH)
    for name in FILES:
        os.makedirs(os.path.join(folder, os.path.dirname(name)), exist_ok=True)
        shutil.copy(os.path.join(ROOT, name), os.path.join(folder, name))
    return folder

def run(folder):
    env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "CI")}
    done = subprocess.run([sys.executable, "scripts/verify-fast-mode-script.py"], cwd=folder,
                          capture_output=True, text=True, env=env, timeout=300)
    last = [line for line in done.stderr.splitlines() if line.startswith(("OK", "FAILED", "Ran "))]
    return done.returncode, " / ".join(last)

bad = 0
folder = tree()
code, summary = run(folder)
shutil.rmtree(folder)
print("baseline (unchanged copies): exit {} {}".format(code, summary))
if code != 0:
    print("baseline does not pass; probe invalid"); sys.exit(1)
for name, path, old, new, control in MUTATIONS:
    folder = tree()
    target = os.path.join(folder, path)
    text = open(target, encoding="utf-8").read()
    count = text.count(old)
    if count != 1:
        print("{}: pattern found {} times, probe invalid".format(name, count)); bad += 1
        shutil.rmtree(folder); continue
    open(target, "w", encoding="utf-8").write(text.replace(old, new))
    code, summary = run(folder)
    shutil.rmtree(folder)
    verdict = "PASSED (drift unnoticed)" if code == 0 else "FAILED (drift caught)"
    print("{:32} {:28} {}: {}".format(name, path, verdict, summary))
    if control and code == 0:
        print("  control did not fail; probe invalid"); bad += 1
    if not control and code == 0:
        bad += 1
print("mutations of copies that no test caught or invalid controls: {}".format(bad))
sys.exit(1 if bad else 0)
