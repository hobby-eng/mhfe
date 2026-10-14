// AUD-024 verifier probe (appended to a scratch copy of src/self_test.rs, never to the repository).
// SelfTest::run documents that its `mhfe` "must be at the default settings". These tests show what
// it does with an engine that is right for the published rounds, at the default settings and at
// other settings, and which settings the vectors it already looks up record.
#[cfg(test)]
mod aud024_verify_settings {
    use super::*;
    use crate::mhfe::known_answers::PublishedRoundKeys;
    use crate::WorkFactor;

    /// The published key for a published input, else a hash of the input: an engine that is right
    /// for every round the vectors record, as a correct Argon2id would be.
    struct Correct;

    impl Argon2Engine for Correct {
        fn derive(
            &mut self,
            password: &[u8],
            salt: &[u8; SALT_BYTES],
            key: &mut [u8; KEY_BYTES],
        ) -> Result<(), MhfeError> {
            if PublishedRoundKeys::of(published_table())
                .derive(password, salt, key)
                .is_err()
            {
                use sha2::Digest;
                key.copy_from_slice(&sha2::Sha256::digest([password, &salt[..]].concat()));
            }
            Ok(())
        }
    }

    fn run_at(pim: u32, memory_level: u32) -> Result<SelfTestResult, MhfeError> {
        let test = SelfTest::published().unwrap();
        let mut mhfe = Mhfe::with_engine(WorkFactor::new(pim, memory_level).unwrap(), Correct);
        let mut rounds = 0;
        let result = test.run(&mut mhfe, &mut |_, _, _| {
            rounds += 1;
            Ok(())
        });
        println!(
            "AUD024 run at PIM {pim}, memory level {memory_level}: {result:?}; {rounds} rounds ran"
        );
        if let Ok(result) = &result {
            if let Some(fault) = result.fault() {
                println!("AUD024   shown fault: {fault}");
            }
        }
        result
    }

    #[test]
    fn aud024_verify_settings_recorded_by_the_vectors_run_looks_up() {
        let test = SelfTest::published().unwrap();
        for name in [test.suite_3_vector(), test.suite_4_vector()] {
            let vector = published_table().iter().find(|v| v.name == name).unwrap();
            println!(
                "AUD024 published table, {name}: pim {}, memory_level {}",
                vector.pim, vector.memory_level
            );
        }
    }

    #[test]
    fn aud024_verify_settings_control_default_passes() {
        let result = run_at(0, 0).unwrap();
        assert!(result.passed());
    }

    #[test]
    fn aud024_verify_settings_pim_1_is_refused() {
        let result = run_at(1, 0);
        assert_eq!(result.err().map(|error| error.code()), Some("INVALID_REQUEST"));
    }

    #[test]
    fn aud024_verify_settings_memory_level_1_is_refused() {
        let result = run_at(0, 1);
        assert_eq!(result.err().map(|error| error.code()), Some("INVALID_REQUEST"));
    }
}
