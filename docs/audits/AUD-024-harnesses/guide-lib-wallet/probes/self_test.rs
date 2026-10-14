// AUD-024 probe: SelfTest::run says its engine "must be at the default settings"; one at PIM 1
// should be refused (as Rekey::recover_state refuses other settings), not reported as a fault.
// The engine hashes its input in place of full-size Argon2.
#[cfg(test)]
mod aud024_probe {
    use super::*;
    use crate::WorkFactor;

    struct Hashing;

    impl Argon2Engine for Hashing {
        fn derive(
            &mut self,
            password: &[u8],
            salt: &[u8; SALT_BYTES],
            key: &mut [u8; KEY_BYTES],
        ) -> Result<(), MhfeError> {
            use sha2::Digest;
            key.copy_from_slice(&sha2::Sha256::digest([password, &salt[..]].concat()));
            Ok(())
        }
    }

    #[test]
    fn aud024_a_self_test_at_other_settings_is_refused() {
        let test = SelfTest::published().unwrap();
        let mut mhfe = Mhfe::with_engine(WorkFactor::new(1, 0).unwrap(), Hashing);
        let result = test.run(&mut mhfe, &mut |_, _, _| Ok(()));
        println!("AUD024 SelfTest::run at PIM 1: {result:?}");
        if let Ok(result) = &result {
            println!("AUD024 its verdict: {}", result.fault().map(|f| f.to_string()).unwrap_or_default());
        }
        assert_eq!(result.err().map(|error| error.code()), Some("INVALID_REQUEST"));
    }
}
