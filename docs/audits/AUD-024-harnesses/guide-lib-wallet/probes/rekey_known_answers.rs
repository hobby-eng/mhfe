// AUD-024 probe: the test a_rekey_is_compared_with_its_target_vector says "A vector of another
// phrase fails"; the failure it accepts should be the comparison with the published container.
#[cfg(test)]
mod aud024_probe {
    use super::*;

    #[test]
    fn aud024_a_rekey_to_another_vector_fails_on_its_comparison() {
        let mut check = RekeyCheck {
            cases: Box::leak(Box::new([RekeyCase {
                from: "zero-12",
                to: "nonzero-12",
                detected: false,
            }])),
        };
        let outcome = check.run(Tier::Startup);
        println!("AUD024 RekeyCheck zero-12 -> nonzero-12: {outcome:?}");
        assert_eq!(
            outcome,
            ComponentOutcome::Failed(
                "rekey 1 of 1 the sealed container differs from the published one".to_owned()
            )
        );
    }
}
