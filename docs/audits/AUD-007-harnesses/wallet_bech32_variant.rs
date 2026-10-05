//! AUD-007: public-vector probe of the Cosmos/Injective checksum-variant boundary.

use bech32::primitives::decode::CheckedHrpstring;
use mhfe::wallet::{find_address, Address, Coin, DerivationPath, SearchLimits};

fn main() {
    // The public BIP39 vector already used by src/wallet.rs; never use a real wallet here.
    let phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    for (coin, text, path) in [
        (
            Coin::Cosmos,
            "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4",
            "m/44'/118'/0'/0/0",
        ),
        (
            Coin::Injective,
            "inj1npvwllfr9dqr8erajqqr6s0vxnk2ak55re90dz",
            "m/44'/60'/0'/0/0",
        ),
    ] {
        let (hrp, payload) = bech32::decode(text).unwrap();
        let wrong_variant = bech32::encode::<bech32::Bech32m>(hrp, &payload).unwrap();
        assert!(CheckedHrpstring::new::<bech32::Bech32>(text).is_ok());
        assert!(CheckedHrpstring::new::<bech32::Bech32>(&wrong_variant).is_err());

        // The audit expects the current bug: changing only the checksum is accepted and
        // preserves the reference match. This assertion should stop passing after repair.
        let parsed = Address::parse(coin, &wrong_variant).unwrap();
        assert_eq!(parsed, Address::parse(coin, text).unwrap());
        let path: DerivationPath = path.parse().unwrap();
        let found =
            find_address(phrase, "", &parsed, Some(&path), SearchLimits::default()).unwrap();
        assert_eq!(found, Some(path));
        println!(
            "{coin:?}: invalid_reference={wrong_variant}; bech32m_reference_accepted=true; invalid_reference_matches=true"
        );
    }
}
