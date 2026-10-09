//! Known answers of hidden wallets: the self-check `hidden-wallets`.
//!
//! A session on the published container zero-24, replayed with its recorded round keys: the
//! wallet a password opens is read at the state's full width, a password is not taken twice, and
//! a reading that passes the built-in check of a shorter phrase is refused (rule I29).

use super::HiddenWallets;
use crate::mhfe::known_answers::{published, published_table};
use crate::self_check::{
    expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};
use crate::Password;

/// The phrase the zero-24 container opens with its own password: 32 zero bytes, "abandon" 23 times
/// and "art". Recomputed independently: its state matches no short length's verifier, and its
/// wallet-check digest with an empty passphrase begins 49f67bdf, which fails, so it is not refused.
const ZERO_24_WALLET: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon abandon abandon abandon abandon art";

/// The `hidden-wallets` check.
pub(crate) struct HiddenWalletsCheck {
    wallet: &'static str,
}

impl HiddenWalletsCheck {
    pub(crate) fn new() -> Self {
        Self {
            wallet: ZERO_24_WALLET,
        }
    }
}

impl ComponentCheck for HiddenWalletsCheck {
    fn id(&self) -> &'static str {
        "hidden-wallets"
    }

    fn label(&self) -> &'static str {
        "Hidden wallets"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        let expected: Vec<&str> = self.wallet.split_whitespace().collect();
        findings.one(|| {
            let vector = published("zero-24")?;
            let mut mhfe = vector.mhfe(published_table())?;
            let mut session = HiddenWallets::new(vector.container, "").map_err(stopped)?;
            let wallet = session
                .open(&mut mhfe, vector.password()?, &mut |_, _| Ok(()))
                .map_err(stopped)?;
            expect(
                wallet.words() == 24
                    && !wallet.verified()
                    && *wallet.phrase() == expected.join(" "),
                "the published container gives another wallet",
            )?;
            // The same password again is refused before any round.
            let again = session.open(&mut mhfe, vector.password()?, &mut |_, _| Ok(()));
            expect_refusal(again.map(|_| ()), "PASSWORD_ALREADY_USED")
                .map_err(|what| format!("a password used twice {what}"))
        });
        // zero-12's own password reads its container as a 12-word phrase that passes its check.
        findings.one(|| {
            let vector = published("zero-12")?;
            let mut mhfe = vector.mhfe(published_table())?;
            let password: Password = vector.password()?;
            let result = mhfe.derive_wallet(vector.container, &password, "", &mut |_, _| Ok(()));
            expect_refusal(result.map(|_| ()), "HIDDEN_WALLET_PASSES_CHECK")
                .map_err(|what| format!("a reading that passes a check {what}"))
        });
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hidden_wallets_pass() {
        assert_eq!(
            HiddenWalletsCheck::new().run(Tier::Startup),
            ComponentOutcome::Passed
        );
    }

    #[test]
    fn another_wallet_fails() {
        let mut check = HiddenWalletsCheck {
            wallet: "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon diesel",
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("the published container gives another wallet".to_owned())
        );
    }
}
