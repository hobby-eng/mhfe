//! The self-test of the core module and the self-checks of its parts, of the process and of the
//! page's Argon2 builds.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{mhfe_with, report, verified};
use crate::engine::browser::JsArgon2;
use crate::engine::{BrowserArgon2Check, BrowserArgon2SizesCheck};
use crate::self_check::{sets, ComponentCheck, SelfCheck};
use crate::self_test::{SelfTest, SelfTestFault};
use crate::wasm_api::{js_error, json, run_self_check};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VectorJson<'a> {
    vector: &'a str,
    as_published: bool,
}

/// Where a self-test that did not pass first left the published path, as the library tells it
/// ([`SelfTestFault`]): its kind, its round, and the sentence a page shows as it is.
#[derive(Serialize)]
struct FaultJson {
    /// "argon2-input", "argon2-key" or "after-argon2".
    kind: &'static str,
    /// 1 to 24; null for "after-argon2".
    round: Option<u32>,
    message: String,
}

impl FaultJson {
    fn of(fault: SelfTestFault) -> Self {
        Self {
            kind: fault.id(),
            round: fault.round(),
            message: fault.to_string(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SelfTestJson<'a> {
    passed: bool,
    suite3: VectorJson<'a>,
    suite4: VectorJson<'a>,
    /// The round of `fault`, 1 to 12 the suite 3 encryption and 13 to 24 the suite 4 recovery,
    /// where Argon2id's input or its key first differed from the published one; null when the
    /// test passed or the fault lies after the last Argon2id call. Only `fault` tells which.
    first_wrong_round: Option<u32>,
    /// Null when the test passed.
    fault: Option<FaultJson>,
}

/// The self-test with the two published vectors at their full cost, PIM 0 and memory level 0: an
/// encryption of suite 3 ("encrypt", rounds 1 to 12 of 24) and a recovery of suite 4 ("recover",
/// rounds 13 to 24). It takes minutes; a page runs it only when the person asks. Returns JSON
/// `{ passed, suite3: { vector, asPublished }, suite4: { vector, asPublished }, firstWrongRound,
/// fault: { kind, round, message } | null }`.
#[wasm_bindgen(js_name = selfTest)]
pub fn self_test(argon2: JsArgon2, on_round: &js_sys::Function) -> Result<String, JsError> {
    let test = SelfTest::published().map_err(js_error)?;
    let (mut mhfe, _) = mhfe_with(test.work(), argon2)?;
    let result = test.run(&mut mhfe, &mut |stage, round, rounds| {
        report(on_round, stage, round, rounds)
    });
    let result = verified(&mhfe, result)?;
    json(&SelfTestJson {
        first_wrong_round: result.first_wrong_round(),
        fault: result.fault().map(FaultJson::of),
        passed: result.passed(),
        suite3: VectorJson {
            vector: test.suite_3_vector(),
            as_published: result.suite_3_as_published(),
        },
        suite4: VectorJson {
            vector: test.suite_4_vector(),
            as_published: result.suite_4_as_published(),
        },
    })
}

/// The self-check of the core module's parts at `tier`, "startup" or "full": the cipher's hashes
/// and rounds, the formats, the container facts and what to keep, passwords, the word list, the
/// repair words, the check word, the wallet's hashes, seeds, keys and addresses, the wallet check,
/// hidden wallets, rekey, missing-word search and the rehearsal check, each with a case it must
/// refuse. With `argon2`,
/// the worker's Argon2 build, it also runs Argon2's known answer through it; without, Argon2 is
/// listed as not run. `skip_ids` leaves out parts that another module of the page has passed
/// already. Returns JSON as described at [`run_self_check`].
#[wasm_bindgen(js_name = selfCheckCore)]
pub fn self_check_core(
    tier: &str,
    skip_ids: Vec<String>,
    argon2: Option<JsArgon2>,
    on_start: &js_sys::Function,
    on_result: &js_sys::Function,
) -> Result<String, JsError> {
    let argon2_check = argon2
        .as_ref()
        .map(|argon2| Box::new(BrowserArgon2Check::new(argon2)) as Box<dyn ComponentCheck + '_>);
    run_self_check(
        sets::core(argon2_check),
        tier,
        &skip_ids,
        on_start,
        on_result,
    )
}

/// The process parts of the command-line tool's self-test as a web page reports them, at `tier`:
/// the memory lock from the library's probe, and core dumps, isolation and hidden input, each not
/// available with the reason ([`sets::browser_process`]). The full self-check of a page runs it.
/// Returns JSON as described at [`run_self_check`].
#[wasm_bindgen(js_name = selfCheckProcess)]
pub fn self_check_process(
    tier: &str,
    skip_ids: Vec<String>,
    on_start: &js_sys::Function,
    on_result: &js_sys::Function,
) -> Result<String, JsError> {
    run_self_check(
        sets::browser_process(),
        tier,
        &skip_ids,
        on_start,
        on_result,
    )
}

/// The self-check of one of the page's Argon2 builds alone at `tier`: its known answer at 1 MiB,
/// and in the full tier at 64 and 256 MiB too, where a browser that cannot give the memory makes
/// that part not available rather than failed. A page runs it for each build in turn, never two at
/// once. `skip_ids` leaves out parts checked already. Returns JSON as described at
/// [`run_self_check`].
#[wasm_bindgen(js_name = selfCheckArgon2)]
pub fn self_check_argon2(
    tier: &str,
    skip_ids: Vec<String>,
    argon2: JsArgon2,
    on_start: &js_sys::Function,
    on_result: &js_sys::Function,
) -> Result<String, JsError> {
    let set = SelfCheck::new()
        .with(BrowserArgon2Check::new(&argon2))
        .with(BrowserArgon2SizesCheck::new(&argon2));
    run_self_check(set, tier, &skip_ids, on_start, on_result)
}
