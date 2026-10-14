// AUD-024 verify-rekey-ka-tests probe, appended to a scratch copy of src/rekey/known_answers.rs.
// The test a_rekey_is_compared_with_its_target_vector (:276-286) says "A vector of another phrase
// fails" and accepts any failure (:285). This probe prints which failure that is, traces the seal
// it stops in, and shows that the comparison of sealed_as (:217-220) can fail when it is reached.
#[cfg(test)]
mod aud024_verify_rekey {
    use super::*;

    #[test]
    fn aud024_rekey_to_another_phrase_fails_on_the_comparison() {
        // V1: the third case of the existing test, run the same way.
        let mut check = RekeyCheck {
            cases: Box::leak(Box::new([RekeyCase {
                from: "zero-12",
                to: "nonzero-12",
                detected: false,
            }])),
        };
        let outcome = check.run(Tier::Startup);
        println!("AUD024 V1 RekeyCheck(zero-12 -> nonzero-12): {outcome:?}");

        // V2: the same steps as RekeyCheck::case and sealed_as, by hand.
        let from = published("zero-12").unwrap();
        let to = published("nonzero-12").unwrap();
        let rekey = Rekey::new(
            from.container,
            PhraseLength::Words(WordCount::new(12).unwrap()),
            from.password().unwrap(),
            from.work().unwrap(),
        )
        .unwrap();
        let confirmed = rekey
            .recover(
                &mut from.mhfe(published_table()).unwrap(),
                Confirmation::BuiltInCheck,
                Some(false),
                &mut |_, _, _| Ok(()),
            )
            .unwrap();
        println!("AUD024 V2 recovery of zero-12 confirmed by its built-in check: ok");
        let sealed = rekey.seal(
            &mut to.mhfe(published_table()).unwrap(),
            &confirmed,
            &to.password().unwrap(),
            None,
            &mut |_, _, _| Ok(()),
            &mut |_| Ok(()),
        );
        match &sealed {
            Ok(_) => println!("AUD024 V2 seal under nonzero-12's password: Ok (comparison reached)"),
            Err(error) => println!(
                "AUD024 V2 seal under nonzero-12's password: Err({}: {error}) before any comparison",
                error.code()
            ),
        }

        // V3: control. A target with unicode-password's password and settings but another
        // container: the seal succeeds and the comparison itself fails.
        let mut changed = *published("unicode-password").unwrap();
        changed.container = from.container;
        let compared = RekeyCheck::sealed_as(&rekey, &confirmed, &changed);
        println!("AUD024 V3 sealed_as(unicode-password with another container): {compared:?}");
        assert_eq!(
            compared,
            Err("the sealed container differs from the published one".to_owned())
        );

        // The claim of the test's comment: the case fails on the comparison.
        assert_eq!(
            outcome,
            ComponentOutcome::Failed(
                "rekey 1 of 1 the sealed container differs from the published one".to_owned()
            ),
            "the test passes on another failure than the comparison it names"
        );
    }
}
