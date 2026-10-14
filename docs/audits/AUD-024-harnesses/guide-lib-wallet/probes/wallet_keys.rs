// AUD-024 probe: CORE-48 asks for an explicit size limit on every input from outside. A BIP39
// passphrase of 8 MiB should be refused before the wallet code reserves eleven times its size.
#[cfg(test)]
mod aud024_probe {
    use super::*;
    use crate::test_support::ABANDON_12 as ABANDON;

    #[test]
    fn aud024_a_passphrase_of_8_mib_is_refused() {
        let passphrase = "a".repeat(8 << 20);
        let normalized = normalized_passphrase(&passphrase);
        println!(
            "AUD024 passphrase of {} bytes: normalized buffer reserved {} bytes",
            passphrase.len(),
            normalized.capacity()
        );
        let started = std::time::Instant::now();
        let fingerprint = crate::wallet::master_fingerprint(ABANDON, &passphrase);
        println!(
            "AUD024 master_fingerprint: {:?} after {:?}",
            fingerprint.as_ref().map(|bytes| hex::encode(bytes)),
            started.elapsed()
        );
        let draw = crate::wallet_check::PhraseDraw::with_check(&passphrase);
        println!("AUD024 PhraseDraw::with_check accepted: {}", draw.is_ok());
        assert!(fingerprint.is_err() && draw.is_err());
    }
}
