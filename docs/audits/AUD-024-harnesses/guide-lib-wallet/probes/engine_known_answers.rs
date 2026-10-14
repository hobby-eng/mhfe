// AUD-024 probe: a_wrong_lane_count_fails says that "The MHFE-shaped call ... with another lane
// count ... gives another tag"; the failure it accepts should be the one of the 1 MiB call.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod aud024_probe {
    use super::*;

    #[test]
    fn aud024_a_wrong_lane_count_fails_on_the_mhfe_shaped_call() {
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
        let mut check = NativeArgon2Check::default();
        check.0.call = two_lanes;
        let outcome = check.run(Tier::Startup);
        println!("AUD024 Argon2 check with two lanes: {outcome:?}");
        assert!(matches!(
            outcome,
            ComponentOutcome::Failed(detail) if detail.ends_with("for the 1 MiB vector")
        ));
    }
}
