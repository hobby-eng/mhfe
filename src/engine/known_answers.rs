//! Known answers of the Argon2id engine: the self-checks `argon2` (startup) and `argon2-sizes`
//! (full self-test only).
//!
//! The checks are closed. Their inputs are private constants, they take no cost and no password,
//! and they give only an outcome, so that no release build holds an engine that computes Argon2
//! below MHFE's own cost (scripts/check-release-artifacts.sh looks for the marker of the one test
//! engine that does). Natively they run the vendored C code on this processor, on each copy of its
//! core that the processor can run, behind the guard the engine puts around every call (a key
//! left unwritten or set to zeros is refused), and confirm that the C code wiped its memory after
//! each call.
//! In a browser they run the page's Emscripten build of the same code through the bridge every
//! operation uses.

#[cfg(not(target_arch = "wasm32"))]
use super::ffi::{self, Argon2Inputs, WorkArea, ARGON2_VERSION_13};
#[cfg(not(target_arch = "wasm32"))]
use super::native::{guarded_call, Call};
use super::{Argon2Cost, KEY_BYTES, SALT_BYTES};
use crate::self_check::{hex, ComponentCheck, ComponentOutcome, Tier};
use crate::MhfeError;

/// The public password and salt of the known answers below, the inputs that
/// scripts/verify-argon2-wasm.mjs gives both Emscripten builds too.
const PASSWORD: &[u8] = b"public test password";
const SALT: &[u8; SALT_BYTES] = b"0123456789abcdef";

/// An Argon2id tag of [`PASSWORD`] and [`SALT`] with MHFE's four lanes and 32 bytes.
#[derive(Clone, Copy)]
struct KnownTag {
    cost: Argon2Cost,
    tag: [u8; KEY_BYTES],
}

impl KnownTag {
    fn mebibytes(self) -> u32 {
        self.cost.memory_kib / 1024
    }
}

/// The tags were computed with OpenSSL through Python cryptography 46.0.5, an implementation
/// independent of the reference C code (scripts/verify-argon2-wasm.mjs, lines 19 to 33).
const SMALL: KnownTag = KnownTag {
    cost: Argon2Cost {
        memory_kib: 1024,
        passes: 1,
    },
    tag: hex("e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2"),
};

/// Larger memory, for the full self-test: many segments, and in a browser a heap that grows.
const SIZES: [KnownTag; 2] = [
    KnownTag {
        cost: Argon2Cost {
            memory_kib: 64 * 1024,
            passes: 3,
        },
        tag: hex("a3931f5728b235c605c02522f3302a8e90d0509a0c3db63ab4d2fcf75f345b5b"),
    },
    KnownTag {
        cost: Argon2Cost {
            memory_kib: 256 * 1024,
            passes: 2,
        },
        tag: hex("4a4a094750f2c17fc6507d38825ec9eac65e10fb2de9e9bf5e801d2af53f1efe"),
    },
];

const ID: &str = "argon2";
const LABEL: &str = "Argon2id";
const SIZES_ID: &str = "argon2-sizes";
const SIZES_LABEL: &str = "Argon2id at 64 and 256 MiB";

/// What a call that returned an error tells: the reference code's own message for an Argon2
/// failure, which names no input, else the error code.
fn could_not_run(error: &MhfeError) -> String {
    match error {
        MhfeError::Argon2(message) => format!("Argon2id could not run: {message}"),
        other => format!("Argon2id could not run: {}", other.code()),
    }
}

/// The RFC 9106 test vector of Argon2id (section 5.3), in which every input differs and the secret
/// and the associated data are set, so that every field of the C context takes part. Only the
/// native build can run it: the Emscripten builds export argon2id_hash_raw, which has neither.
#[cfg(not(target_arch = "wasm32"))]
mod rfc_9106 {
    pub(super) const PASSWORD: [u8; 32] = [0x01; 32];
    pub(super) const SALT: [u8; 16] = [0x02; 16];
    pub(super) const SECRET: [u8; 8] = [0x03; 8];
    pub(super) const ASSOCIATED_DATA: [u8; 12] = [0x04; 12];
    pub(super) const PASSES: u32 = 3;
    pub(super) const MEMORY_KIB: u32 = 32;
    pub(super) const LANES: u32 = 4;
    pub(super) const TAG: [u8; 32] =
        crate::self_check::hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
}

/// The copies of the Argon2 core this processor runs, by name: on x86-64 the SSE2 copy, and the
/// SSSE3 copy where the processor has SSSE3; elsewhere the one core of the build.
#[cfg(not(target_arch = "wasm32"))]
fn cores() -> Vec<(bool, &'static str)> {
    if cfg!(target_arch = "x86_64") {
        let mut cores = vec![(false, "the SSE2 core")];
        if super::native::processor_has_ssse3() {
            cores.push((true, "the SSSE3 core"));
        }
        cores
    } else {
        vec![(false, "the Argon2 core")]
    }
}

/// The startup check of the native Argon2id engine: on each copy of the core, the RFC 9106 vector
/// and a call shaped as MHFE makes it at 1 MiB (four lanes on four threads, version 1.3, no secret
/// or associated data, built by the engine's own code), each in the same 1 MiB work area, which
/// must be wiped after every call, and each behind the engine's written-key guard. About two to
/// three milliseconds. It starts four threads per call and joins them before it returns: the
/// command-line tool runs it after a command started directly has entered its own network
/// namespace, which needs a process of a single thread, and, for the start menu, before the menu
/// opens, with no network namespace (a command of the menu runs in a thread of the menu).
#[cfg(not(target_arch = "wasm32"))]
pub struct NativeArgon2Check {
    small: KnownTag,
    rfc_tag: [u8; KEY_BYTES],
    call: Call,
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeArgon2Check {
    pub fn new() -> Self {
        Self {
            small: SMALL,
            rfc_tag: rfc_9106::TAG,
            call: ffi::argon2id,
        }
    }

    /// The RFC 9106 call on `core`.
    fn rfc_inputs(ssse3: bool) -> Argon2Inputs<'static> {
        Argon2Inputs {
            password: &rfc_9106::PASSWORD,
            salt: &rfc_9106::SALT,
            secret: &rfc_9106::SECRET,
            associated_data: &rfc_9106::ASSOCIATED_DATA,
            passes: rfc_9106::PASSES,
            memory_kib: rfc_9106::MEMORY_KIB,
            lanes: rfc_9106::LANES,
            threads: rfc_9106::LANES,
            version: ARGON2_VERSION_13,
            ssse3,
        }
    }

    fn check(&self) -> Result<(), String> {
        let mut work_area = WorkArea::allocate(self.small.cost.memory_bytes())
            .map_err(|error| could_not_run(&error))?;
        for (ssse3, core) in cores() {
            let rfc = Self::rfc_inputs(ssse3);
            let mhfe = super::native::mhfe_inputs(PASSWORD, SALT, self.small.cost, ssse3);
            for (inputs, expected, vector) in [
                (&rfc, &self.rfc_tag, "the RFC 9106 vector"),
                (&mhfe, &self.small.tag, "the 1 MiB vector"),
            ] {
                let mut tag = [0u8; KEY_BYTES];
                guarded_call(self.call, inputs, &mut work_area, &mut tag)
                    .map_err(|error| could_not_run(&error))?;
                if tag != *expected {
                    return Err(format!("{core} gives another tag for {vector}"));
                }
                if !work_area.is_wiped() {
                    return Err(format!("{core} leaves its memory unwiped"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for NativeArgon2Check {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl ComponentCheck for NativeArgon2Check {
    fn id(&self) -> &'static str {
        ID
    }

    fn label(&self) -> &'static str {
        LABEL
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        match self.check() {
            Ok(()) => ComponentOutcome::Passed,
            Err(detail) => ComponentOutcome::Failed(detail),
        }
    }
}

/// The full self-test's check of the native engine at 64 and 256 MiB, on each copy of the core,
/// with four threads and, once, with one: indexing over many segments and the threads. About half
/// a second per copy and 256 MiB. A computer that cannot reserve the memory is told apart from a
/// wrong answer: that part is not available here, rather than failed.
#[cfg(not(target_arch = "wasm32"))]
pub struct NativeArgon2SizesCheck {
    sizes: [KnownTag; 2],
    call: Call,
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeArgon2SizesCheck {
    pub fn new() -> Self {
        Self {
            sizes: SIZES,
            call: ffi::argon2id,
        }
    }

    fn check(&self) -> ComponentOutcome {
        let largest = self.sizes[1].cost.memory_bytes();
        let mut work_area = match WorkArea::allocate(largest) {
            Ok(work_area) => work_area,
            Err(_) => {
                return ComponentOutcome::NotAvailable(format!(
                    "the computer could not reserve {} MiB",
                    largest >> 20
                ))
            }
        };
        let mut runs = Vec::new();
        for (index, (ssse3, core)) in cores().into_iter().enumerate() {
            for size in self.sizes {
                runs.push((ssse3, core, size, super::LANES));
            }
            if index == 0 {
                // Four lanes on one thread must give the tag of four threads.
                runs.push((ssse3, core, self.sizes[0], 1));
            }
        }
        for (ssse3, core, size, threads) in runs {
            let mut inputs = super::native::mhfe_inputs(PASSWORD, SALT, size.cost, ssse3);
            inputs.threads = threads;
            let mut tag = [0u8; KEY_BYTES];
            match guarded_call(self.call, &inputs, &mut work_area, &mut tag) {
                Err(MhfeError::MemoryAllocation { .. }) => {
                    return ComponentOutcome::NotAvailable(format!(
                        "the computer could not reserve {} MiB",
                        size.mebibytes()
                    ))
                }
                Err(error) => return ComponentOutcome::Failed(could_not_run(&error)),
                Ok(()) if tag != size.tag => {
                    let threads = if threads == 1 { " on one thread" } else { "" };
                    return ComponentOutcome::Failed(format!(
                        "{core} gives another tag at {} MiB{threads}",
                        size.mebibytes()
                    ));
                }
                Ok(()) if !work_area.is_wiped() => {
                    return ComponentOutcome::Failed(format!(
                        "{core} leaves its memory unwiped at {} MiB",
                        size.mebibytes()
                    ))
                }
                Ok(()) => {}
            }
        }
        debug_assert!(work_area.bytes() as u64 >= largest);
        ComponentOutcome::Passed
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for NativeArgon2SizesCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl ComponentCheck for NativeArgon2SizesCheck {
    fn id(&self) -> &'static str {
        SIZES_ID
    }

    fn label(&self) -> &'static str {
        SIZES_LABEL
    }

    fn runs_at(&self, tier: Tier) -> bool {
        tier == Tier::Full
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        self.check()
    }
}

#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
use super::browser::{derive_with, JsArgon2};

/// The check of the page's Argon2 build: the 1 MiB known answer through the same bridge every
/// round of an operation uses, so that a build that gives zeros, writes into a stale view of the
/// WebAssembly memory or another wrong tag is found. Half a millisecond once the build runs. An
/// operation runs [`BrowserArgon2Check::verify`] before its first round and after its last, which
/// also covers the optimized code a browser makes of a long-running loop.
#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
pub struct BrowserArgon2Check<'a> {
    argon2: &'a JsArgon2,
}

#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
impl<'a> BrowserArgon2Check<'a> {
    pub fn new(argon2: &'a JsArgon2) -> Self {
        Self { argon2 }
    }

    /// The known answer once: `Ok`, or [`MhfeError::SelfCheckFailed`] naming what went wrong.
    pub fn verify(&self) -> Result<(), MhfeError> {
        self.check().map_err(|detail| MhfeError::SelfCheckFailed {
            component: LABEL.to_owned(),
            detail,
        })
    }

    fn check(&self) -> Result<(), String> {
        let mut tag = [0u8; KEY_BYTES];
        derive_with(self.argon2, PASSWORD, SALT, SMALL.cost, &mut tag)
            .map_err(|error| could_not_run(&error))?;
        if tag == SMALL.tag {
            Ok(())
        } else {
            Err("the page's Argon2 build gives another tag".to_owned())
        }
    }
}

#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
impl ComponentCheck for BrowserArgon2Check<'_> {
    fn id(&self) -> &'static str {
        ID
    }

    fn label(&self) -> &'static str {
        LABEL
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        match self.check() {
            Ok(()) => ComponentOutcome::Passed,
            Err(detail) => ComponentOutcome::Failed(detail),
        }
    }
}

/// The full self-test's check of one of the page's Argon2 builds at 64 and 256 MiB: the heap must
/// grow and the bridge read the grown memory. A page runs it for the single-threaded build and
/// then for the threaded one, never both at once. A browser that cannot give the memory makes the
/// part not available here, rather than failed.
#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
pub struct BrowserArgon2SizesCheck<'a> {
    argon2: &'a JsArgon2,
}

#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
impl<'a> BrowserArgon2SizesCheck<'a> {
    pub fn new(argon2: &'a JsArgon2) -> Self {
        Self { argon2 }
    }
}

#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
impl ComponentCheck for BrowserArgon2SizesCheck<'_> {
    fn id(&self) -> &'static str {
        SIZES_ID
    }

    fn label(&self) -> &'static str {
        SIZES_LABEL
    }

    fn runs_at(&self, tier: Tier) -> bool {
        tier == Tier::Full
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        for size in SIZES {
            let mut tag = [0u8; KEY_BYTES];
            match derive_with(self.argon2, PASSWORD, SALT, size.cost, &mut tag) {
                Err(MhfeError::MemoryAllocation { .. }) => {
                    return ComponentOutcome::NotAvailable(format!(
                        "the browser could not give {} MiB",
                        size.mebibytes()
                    ))
                }
                Err(error) => return ComponentOutcome::Failed(could_not_run(&error)),
                Ok(()) if tag != size.tag => {
                    return ComponentOutcome::Failed(format!(
                        "the page's Argon2 build gives another tag at {} MiB",
                        size.mebibytes()
                    ))
                }
                Ok(()) => {}
            }
        }
        ComponentOutcome::Passed
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn the_engine_passes_its_known_answers() {
        let mut check = NativeArgon2Check::new();
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        assert_eq!((check.id(), check.label()), ("argon2", "Argon2id"));
        assert!(check.runs_at(Tier::Startup));
    }

    #[test]
    fn a_corrupted_tag_fails() {
        let mut small = NativeArgon2Check::new();
        small.small.tag[31] ^= 1;
        assert_eq!(
            small.run(Tier::Startup),
            ComponentOutcome::Failed(format!(
                "{} gives another tag for the 1 MiB vector",
                cores()[0].1
            ))
        );
        let mut rfc = NativeArgon2Check::new();
        rfc.rfc_tag[0] ^= 0x80;
        assert!(matches!(
            rfc.run(Tier::Startup),
            ComponentOutcome::Failed(detail) if detail.ends_with("for the RFC 9106 vector")
        ));
    }

    /// The MHFE-shaped call is the engine's own: a call with another lane count, as a broken
    /// parameter assembly would make, gives another tag.
    #[test]
    fn a_wrong_lane_count_fails() {
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
        let mut check = NativeArgon2Check::new();
        check.call = two_lanes;
        assert!(check.run(Tier::Startup).is_failure());
    }

    #[test]
    fn a_failing_call_is_told_apart_from_a_wrong_tag() {
        fn refused(_: &Argon2Inputs<'_>, _: &mut WorkArea, _: &mut [u8]) -> Result<(), MhfeError> {
            Err(MhfeError::Argon2("Threading failure".to_owned()))
        }
        let mut check = NativeArgon2Check::new();
        check.call = refused;
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("Argon2id could not run: Threading failure".to_owned())
        );
    }

    /// The checks put the engine's guard around every call: a call that returns without writing
    /// the key, or writes only zeros, is refused as the engine refuses it, not merely compared.
    #[test]
    fn a_call_that_writes_no_key_is_refused_by_the_guard() {
        fn writes_nothing(
            _: &Argon2Inputs<'_>,
            _: &mut WorkArea,
            _: &mut [u8],
        ) -> Result<(), MhfeError> {
            Ok(())
        }
        fn writes_zeros(
            _: &Argon2Inputs<'_>,
            _: &mut WorkArea,
            tag: &mut [u8],
        ) -> Result<(), MhfeError> {
            tag.fill(0);
            Ok(())
        }
        let refused = ComponentOutcome::Failed(
            "Argon2id could not run: the Argon2 engine returned without writing the key".to_owned(),
        );
        for call in [writes_nothing as Call, writes_zeros] {
            let mut check = NativeArgon2Check::new();
            check.call = call;
            assert_eq!(check.run(Tier::Startup), refused);
            let mut sizes = NativeArgon2SizesCheck::new();
            sizes.call = call;
            assert_eq!(sizes.run(Tier::Full), refused);
        }
    }

    #[test]
    fn a_call_that_leaves_its_memory_unwiped_fails() {
        fn leaves_blocks(
            inputs: &Argon2Inputs<'_>,
            work_area: &mut WorkArea,
            tag: &mut [u8],
        ) -> Result<(), MhfeError> {
            ffi::argon2id(inputs, work_area, tag)?;
            work_area.fill_for_tests(0x5a);
            Ok(())
        }
        let mut check = NativeArgon2Check::new();
        check.call = leaves_blocks;
        assert!(matches!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(detail) if detail.ends_with("leaves its memory unwiped")
        ));
    }

    #[test]
    fn the_sizes_run_in_the_full_self_test_only() {
        let mut check = NativeArgon2SizesCheck::new();
        assert!(!check.runs_at(Tier::Startup));
        assert!(check.runs_at(Tier::Full));
        assert_eq!(check.run(Tier::Full), ComponentOutcome::Passed);
        check.sizes[1].tag[5] ^= 4;
        assert!(matches!(
            check.run(Tier::Full),
            ComponentOutcome::Failed(detail) if detail.ends_with("gives another tag at 256 MiB")
        ));
    }

    /// The checks take no cost and no password, and are no Argon2 engine: they cannot be used to
    /// compute anything but their own known answers. The engine part is checked when the test
    /// compiles: if a check implemented [`Argon2Engine`], both impls of `NoEngine` below would
    /// apply and the call would be ambiguous (the technique of static_assertions'
    /// assert_not_impl_any).
    #[test]
    fn the_checks_are_closed() {
        use crate::engine::Argon2Engine;
        trait NoEngine<Marker> {
            fn closed() {}
        }
        impl<T: ?Sized> NoEngine<()> for T {}
        struct IsAnEngine;
        impl<T: ?Sized + Argon2Engine> NoEngine<IsAnEngine> for T {}
        <NativeArgon2Check as NoEngine<_>>::closed();
        <NativeArgon2SizesCheck as NoEngine<_>>::closed();

        fn takes_nothing<C: ComponentCheck>(_: fn() -> C) {}
        takes_nothing(NativeArgon2Check::new);
        takes_nothing(NativeArgon2SizesCheck::new);
    }
}
