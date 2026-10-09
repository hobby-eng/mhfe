// Compile-only witness: safe public API can relocate the buffer while its private guard remains.
// No encryption, recovery, secrets or runtime memory-erasure measurement is performed here.
pub fn relocate_recovered_phrase(recovered: &mut mhfe::RecoveredPhrase) {
    const EXTRA_CAPACITY: usize = 1024 * 1024;
    recovered.phrase.reserve(EXTRA_CAPACITY);
    recovered.phrase.push_str(" synthetic extension");
}
