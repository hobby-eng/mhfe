//! Compile-only witness for AUD-012-SEC002 remediation. No recovery or secret input is used.

pub fn read(recovered: &mhfe::RecoveredPhrase) -> &str {
    recovered.phrase()
}

pub fn consume(recovered: mhfe::RecoveredPhrase) -> mhfe::memory::LockedText {
    recovered.into_phrase()
}
