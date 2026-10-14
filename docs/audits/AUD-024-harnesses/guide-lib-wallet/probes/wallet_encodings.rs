// AUD-024 probe: CORE-48 and CORE-50 ask for explicit limits; an address text far longer than any
// address (here 32,000 characters) should be refused at once, not decoded whole. The Base58
// decoder takes time that grows with the square of the length.
#[cfg(test)]
mod aud024_probe {
    use super::*;

    #[test]
    fn aud024_a_long_address_text_is_refused_at_once() {
        let mut slowest = std::time::Duration::ZERO;
        for length in [8_000usize, 16_000, 32_000] {
            let text = "2".repeat(length);
            let started = std::time::Instant::now();
            let result = Address::parse(Coin::Bitcoin, &text);
            let elapsed = started.elapsed();
            slowest = slowest.max(elapsed);
            println!(
                "AUD024 Base58 text of {length} characters: {:?} after {elapsed:?}",
                result.as_ref().map_err(MhfeError::code).err()
            );
        }
        assert!(slowest < std::time::Duration::from_millis(50));
    }
}
