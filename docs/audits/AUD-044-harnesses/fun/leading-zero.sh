#!/usr/bin/env bash
# AUD-044 fun probe: hardened children of parent keys with a leading zero byte, independent values.
../tmp/aud044/target/release/fun-probes addresses < ../tmp/aud044/fun/work/leading-zero.txt
