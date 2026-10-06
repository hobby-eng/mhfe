# AUD-008 scoped research ranking

This harness belongs to reviewer 11's optional-improvement contribution to AUD-008. It binds seven ranked opportunities to exact source lines and shared audit evidence. It confirms record consistency only; it does not test the proposed implementations or establish release acceptance.

The reviewed commit is `b6993bb1c11834a01847d1812b31a24145ab1f18`, with the coordinator's dirty-source fingerprint `9e5357c0b085c7f68ec3c30b6940147b2aaaf89bb8f6dcbf9ea0d2d6593c790a`. Existing owner fixes in `wallet.rs` and `hidden_input.rs` are part of that baseline. The read-only specification pin is `28e50e049d48cf1d5a8a529380192b6371458a57`.

Inputs are the authoritative checkout, canonical procedure files in `../multi-chain-wallet-tools`, and local-only `docs/audits/AUD-008-evidence/{research-review,snapshot}.json` plus the nine shared reviewer records named by the research record. The local records are deliberately ignored and are not public release inputs. No secrets, provider data, build, Argon2, browser, terminal or network operation is needed.

From the repository root, run:

```sh
python3 docs/audits/AUD-008-harnesses/research-static.py
```

Expected output reports seven opportunities and an empty `errors` list. Exit code 0 means source/evidence hashes, line references, duplicate-key rejection, rankings and scoped dispositions agree; any mismatch exits 1. Local `research-static.json` retains the exact source excerpts. The coordinator remains responsible for the aggregate report schema, final finding IDs, paired Markdown and JSON, and heavy verification. An absent local input is an incomplete rerun, not a product defect.

To retain a command ledger with a fresh unique label:

```sh
python3 docs/audits/AUD-008-harnesses/record-command.py --label research-static --timeout 30 -- python3 docs/audits/AUD-008-harnesses/research-static.py
```

The ranking proposes no cipher redesign or new supported coin. Confirmed findings remain in their existing owners' records. Assistive-terminal usability and long-term platform availability are unresolved evidence questions, not security claims.
