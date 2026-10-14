#!/usr/bin/env python3
"""AUD-024 verifier probe: the documented browser check()/rekey()/keepOldContainer() shape against
web/client.d.ts and the WebAssembly exports. Run from the mhfe root. Exits 1 if any doc is stale."""
import pathlib, re, sys
R = pathlib.Path.cwd()
fails = 0
def rep(ok, t):
    global fails
    print(("ok    " if ok else "FAIL  ") + t); fails += 0 if ok else 1
def lines(p): return (R / p).read_text().splitlines()
dts = (R / "web/client.d.ts").read_text()
rep("outcome: MhfeCheckOutcome;" in dts, "client.d.ts: check() resolves to { outcome, path, evidence }")
rep(not re.search(r"^\s*matches\s*:", dts, re.M), "client.d.ts: no `matches` field declared")
rep("matchingLengths: number[];" in dts and "passed: (" in dts, "client.d.ts: evidence has matchingLengths and passed")
rep("rehearsal: MhfeReplacementRehearsal;" in dts, "client.d.ts: rekey() result has rehearsal")
rep("keepOldContainer(options?" in dts, "client.d.ts: MhfeClient.keepOldContainer() declared")
core = (R / "src/wasm_api/core.rs").read_text()
rep("js_name = keepOldContainer" in core, "src/wasm_api/core.rs exports keepOldContainer")
for doc in ("docs/API.md", "docs/BROWSER-PACKAGE.md", "dist/README.md"):
    if not (R / doc).exists():
        print(f"skip  {doc} absent"); continue
    L = lines(doc)
    stale = [i + 1 for i, l in enumerate(L) if re.search(r"\{ matches, path, evidence|matches is true|evidence: \{ builtInCheck, walletCheck \}", l)]
    rep(not stale, f"{doc}: check() documented with a `matches` field / two-field evidence: lines {stale}")
api = lines("docs/API.md")
start = next(i for i, l in enumerate(api) if "// core/client.js" in l)
end = next(i for i in range(start, len(api)) if "// repair/repair.js" in api[i])
sect = "\n".join(api[start:end])
rep("keepOldContainer" in sect, f"docs/API.md MhfeClient listing (lines {start+1}-{end}) names keepOldContainer()")
rep("rehearsal" in sect, f"docs/API.md MhfeClient listing (lines {start+1}-{end}) names the rekey result's rehearsal")
exp = next(i for i, l in enumerate(api) if l.startswith("The WebAssembly's exports are in"))
exports = " ".join(api[exp:exp + 8])
rep("`keepOldContainer`" in exports, f"docs/API.md exports list (line {exp+1}) names keepOldContainer")
claim = [i + 1 for i, l in enumerate(api) if "when the built-in check of any 12- to 21-word length passes" in l]
rep(not claim, f"docs/API.md: no 'any length passes' matching rule for {{ words: n }} (lines {claim})")
print(f"{fails} check(s) failed"); sys.exit(1 if fails else 0)
