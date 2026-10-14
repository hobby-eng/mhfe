// AUD-024 verify-rekey-ka-tests probe, appended to a scratch copy of src/engine/known_answers.rs.
// The test a_wrong_lane_count_fails (:427-444) says that the MHFE-shaped call with another lane
// count gives another tag, and accepts any failure (:443). This probe prints which failure that is,
// and what the check gives when only the MHFE-shaped call (empty secret) gets two lanes.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod aud024_verify_lanes {
    use super::*;

    fn two_lanes(
        inputs: &Argon2Inputs<'_>,
        work_area: &mut WorkArea,
        tag: &mut [u8],
    ) -> Result<(), MhfeError> {
        let mut changed = Argon2Inputs { ..*inputs };
        changed.lanes = 2;
        changed.threads = 2;
        ffi::argon2id(&changed, work_area, tag)
    }

    /// Two lanes for the MHFE-shaped call only: the RFC 9106 call has a secret, MHFE's has none.
    fn two_lanes_mhfe_only(
        inputs: &Argon2Inputs<'_>,
        work_area: &mut WorkArea,
        tag: &mut [u8],
    ) -> Result<(), MhfeError> {
        let mut changed = Argon2Inputs { ..*inputs };
        if inputs.secret.is_empty() {
            changed.lanes = 2;
            changed.threads = 2;
        }
        ffi::argon2id(&changed, work_area, tag)
    }

    #[test]
    fn aud024_a_wrong_lane_count_fails_on_the_mhfe_shaped_call() {
        let mut check = NativeArgon2Check::default();
        check.0.call = two_lanes;
        let outcome = check.run(Tier::Startup);
        println!("AUD024 L1 the test's own two-lane call: {outcome:?}");

        let mut check = NativeArgon2Check::default();
        check.0.call = two_lanes_mhfe_only;
        let only_mhfe = check.run(Tier::Startup);
        println!("AUD024 L2 two lanes for the MHFE-shaped call only: {only_mhfe:?}");
        assert!(matches!(
            &only_mhfe,
            ComponentOutcome::Failed(detail) if detail.ends_with("for the 1 MiB vector")
        ));

        // The claim of the test's doc comment: the MHFE-shaped call is what fails.
        assert!(
            matches!(
                &outcome,
                ComponentOutcome::Failed(detail) if detail.ends_with("for the 1 MiB vector")
            ),
            "the test passes on another failure than the MHFE-shaped call it names"
        );
    }
}
