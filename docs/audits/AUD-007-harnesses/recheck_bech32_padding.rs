//! AUD-007 follow-up: public account vectors with a redundant five-bit data group.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Fe32, Fe32IterExt};
use mhfe::wallet::{Address, Coin};

fn main() {
    for (coin, text) in [
        (
            Coin::Cosmos,
            "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4",
        ),
        (
            Coin::Injective,
            "inj1npvwllfr9dqr8erajqqr6s0vxnk2ak55re90dz",
        ),
    ] {
        let original = Address::parse(coin, text).unwrap();
        let checked = CheckedHrpstring::new::<Bech32>(text).unwrap();
        let data: Vec<Fe32> = checked.fe32_iter().collect();
        assert_eq!(data.len(), 32); // 20 bytes account data, exactly 160 bits.
        for extra in [Fe32::Q, Fe32::P] {
            let malformed: String = data
                .iter()
                .copied()
                .chain(std::iter::once(extra))
                .with_checksum::<Bech32>(&checked.hrp())
                .chars()
                .collect();
            let decoded = CheckedHrpstring::new::<Bech32>(&malformed).unwrap();
            assert!(decoded.validate_segwit_padding().is_err());
            let accepted = Address::parse(coin, &malformed);
            println!(
                "{coin:?}: malformed={malformed}; data_groups={}; accepted={}; same_reference={}",
                decoded.data_part_ascii_no_checksum().len(),
                accepted.is_ok(),
                accepted.as_ref().is_ok_and(|address| address == &original)
            );
            // This is a finding probe: success reproduces the missing padding check.
            assert_eq!(accepted.unwrap(), original);
        }
    }
}
