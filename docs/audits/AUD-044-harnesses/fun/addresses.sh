#!/usr/bin/env bash
# AUD-044 fun probe: every address of an independent Python derivation, read and found by the library.
python3 -I ../tmp/aud044/fun/independent_addresses.py | tee ../tmp/aud044/fun/work/addresses.txt | ../tmp/aud044/target/release/fun-probes addresses
