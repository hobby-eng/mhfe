# AUD-044 fun probes

Run from the repository root; `../tmp/aud044/fun` holds the reduced-cost program built by `reduced-cli`
(`mhfe-reduced`) and the working files. `probes` is a crate over the library of this checkout, built
with `CARGO_TARGET_DIR=../tmp/aud044/target cargo build --release --offline` in its folder. Public test
data only: the phrase "abandon ... about", the published vectors and containers derived from them.
