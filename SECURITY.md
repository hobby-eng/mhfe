# MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics — Security

MHFE (Memory-Hard Feistel Encryption for BIP39 Mnemonics) is experimental research
software. It has an internal implementation audit but no independent cryptography-specialist
review. Do not use it to protect real funds. A successful build, test-vector match, or round trip
does not establish cryptographic security. The protocol and its security limitations are described
in the [companion specification](https://github.com/hobby-eng/mhfe-spec).

Report suspected implementation vulnerabilities privately through GitHub's
security-advisory interface for this repository. Never include a real recovery
phrase, password, private key, wallet export, or other secret in a report.

The browser Worker is a responsiveness and cancellation boundary. It is not a
security vault. The browser API performs no network requests; consuming
applications are responsible for retaining an offline CSP and preventing
secret-bearing network access.

Operational APIs avoid vector-only intermediate strings. Reachable password,
mnemonic, packed-state, round-material, result, and Argon2 work buffers are
zeroized where their Rust ownership permits. This is memory-hygiene defense in
depth, not a claim that a compiler, browser, operating system, swap device, or
hardware cannot retain copies.
