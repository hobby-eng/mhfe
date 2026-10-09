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
/// The parts of a self-check that run Argon2, which a page names to skip or to mark: the known
/// answer at 1 MiB, then the one at 64 and 256 MiB.
#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
pub(crate) const PART_IDS: [&str; 2] = [ID, SIZES_ID];

/// What a call that returned an error tells: the reference code's own message for an Argon2
/// failure, which names no input, else the error code.
fn could_not_run(error: &MhfeError) -> String {
    match error {
        MhfeError::Argon2(message) => format!("Argon2id could not run: {message}"),
        other => format!("Argon2id could not run: {}", other.code()),
    }
}

/// What a build of Argon2 answers its known answers with: the native engine on each copy of its
/// core, or a page's Emscripten build through the bridge. The two parts of a self-check below ask
/// it, so that both builds report under the same ids, labels and tiers.
trait Argon2Answers {
    /// The known answer at 1 MiB: `Err` names what went wrong.
    fn small(&self) -> Result<(), String>;
    /// The known answers at 64 and 256 MiB, with a size the computer cannot give told apart.
    fn sizes(&self) -> ComponentOutcome;
}

/// The startup part `argon2`: the known answer of `A` at 1 MiB.
#[derive(Default)]
pub struct Argon2Check<A>(A);

/// The full self-test's part `argon2-sizes`: the known answers of `A` at 64 and 256 MiB.
#[derive(Default)]
pub struct Argon2SizesCheck<A>(A);

impl<A: Argon2Answers> ComponentCheck for Argon2Check<A> {
    fn id(&self) -> &'static str {
        ID
    }

    fn label(&self) -> &'static str {
        LABEL
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        self.0.small().into()
    }
}

impl<A: Argon2Answers> ComponentCheck for Argon2SizesCheck<A> {
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
        self.0.sizes()
    }
}

/// The RFC 9106 test vector of Argon2id (section 5.3), in which every input differs and the secret
/// and the associated data are set, so that every field of the C context takes part. Only the
/// native build can run it: the Emscripten builds export argon2id_hash_raw, which has neither.
#[cfg(not(target_arch = "wasm32"))]
pub(in crate::engine) mod rfc_9106 {
    pub(in crate::engine) const PASSWORD: [u8; 32] = [0x01; 32];
    pub(in crate::engine) const SALT: [u8; 16] = [0x02; 16];
    pub(in crate::engine) const SECRET: [u8; 8] = [0x03; 8];
    pub(in crate::engine) const ASSOCIATED_DATA: [u8; 12] = [0x04; 12];
    pub(in crate::engine) const PASSES: u32 = 3;
    pub(in crate::engine) const MEMORY_KIB: u32 = 32;
    pub(in crate::engine) const LANES: u32 = 4;
    pub(in crate::engine) const TAG: [u8; 32] =
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

/// The known answers of the native Argon2id engine, which `call` computes behind the engine's
/// written-key guard.
///
/// At startup ([`NativeArgon2Check`]), on each copy of the core, the RFC 9106 vector and a call
/// shaped as MHFE makes it at 1 MiB (four lanes on four threads, version 1.3, no secret or
/// associated data, built by the engine's own code), each in the same 1 MiB work area, which must
/// be wiped after every call. About two to three milliseconds. It starts four threads per call and
/// joins them before it returns: the command-line tool runs it after a command started directly
/// has entered its own network namespace, which needs a process of a single thread, and, for the
/// start menu, before the menu opens, with no network namespace (a command of the menu runs in a
/// thread of the menu).
///
/// In the full self-test ([`NativeArgon2SizesCheck`]), the same at 64 and 256 MiB, on each copy of
/// the core, with four threads and, once, with one: indexing over many segments and the threads.
/// About half a second per copy and 256 MiB. A computer that cannot reserve the memory is told
/// apart from a wrong answer: that part is not available here, rather than failed.
#[cfg(not(target_arch = "wasm32"))]
pub struct NativeArgon2 {
    small: KnownTag,
    rfc_tag: [u8; KEY_BYTES],
    sizes: [KnownTag; 2],
    call: Call,
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for NativeArgon2 {
    fn default() -> Self {
        Self {
            small: SMALL,
            rfc_tag: rfc_9106::TAG,
            sizes: SIZES,
            call: ffi::argon2id,
        }
    }
}

/// The startup part `argon2` of the native engine.
#[cfg(not(target_arch = "wasm32"))]
pub type NativeArgon2Check = Argon2Check<NativeArgon2>;
/// The full self-test's part `argon2-sizes` of the native engine.
#[cfg(not(target_arch = "wasm32"))]
pub type NativeArgon2SizesCheck = Argon2SizesCheck<NativeArgon2>;

#[cfg(not(target_arch = "wasm32"))]
impl NativeArgon2 {
    /// The RFC 9106 call, on the SSSE3 copy of the core if `ssse3`.
    pub(in crate::engine) fn rfc_inputs(ssse3: bool) -> Argon2Inputs<'static> {
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
}

#[cfg(not(target_arch = "wasm32"))]
impl Argon2Answers for NativeArgon2 {
    fn small(&self) -> Result<(), String> {
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

    fn sizes(&self) -> ComponentOutcome {
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

#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
use super::browser::{derive_with, JsArgon2};

/// The known answers of one of the page's Argon2 builds, through the same bridge every round of an
/// operation uses.
///
/// At startup ([`BrowserArgon2Check`]) the 1 MiB known answer, so that a build that gives zeros,
/// writes into a stale view of the WebAssembly memory or another wrong tag is found. Half a
/// millisecond once the build runs. An operation runs [`BrowserArgon2Check::verify`] before its
/// first round and after its last, which also covers the optimized code a browser makes of a
/// long-running loop.
///
/// In the full self-test ([`BrowserArgon2SizesCheck`]) the known answers at 64 and 256 MiB: the
/// heap must grow and the bridge read the grown memory. A page runs it for the single-threaded
/// build and then for the threaded one, never both at once. A browser that cannot give the memory
/// makes the part not available here, rather than failed.
#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
pub struct PageArgon2<'a> {
    argon2: &'a JsArgon2,
}

/// The startup part `argon2` of a page's Argon2 build.
#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
pub type BrowserArgon2Check<'a> = Argon2Check<PageArgon2<'a>>;
/// The full self-test's part `argon2-sizes` of a page's Argon2 build.
#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
pub type BrowserArgon2SizesCheck<'a> = Argon2SizesCheck<PageArgon2<'a>>;

#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
impl<'a> Argon2Check<PageArgon2<'a>> {
    pub fn new(argon2: &'a JsArgon2) -> Self {
        Self(PageArgon2 { argon2 })
    }

    /// The known answer once: `Ok`, or [`MhfeError::SelfCheckFailed`] naming what went wrong.
    pub fn verify(&self) -> Result<(), MhfeError> {
        self.0.small().map_err(|detail| MhfeError::SelfCheckFailed {
            component: LABEL.to_owned(),
            detail,
        })
    }
}

#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
impl<'a> Argon2SizesCheck<PageArgon2<'a>> {
    pub fn new(argon2: &'a JsArgon2) -> Self {
        Self(PageArgon2 { argon2 })
    }
}

#[cfg(all(feature = "browser-core", target_arch = "wasm32"))]
impl Argon2Answers for PageArgon2<'_> {
    fn small(&self) -> Result<(), String> {
        let mut tag = [0u8; KEY_BYTES];
        derive_with(self.argon2, PASSWORD, SALT, SMALL.cost, &mut tag)
            .map_err(|error| could_not_run(&error))?;
        if tag == SMALL.tag {
            Ok(())
        } else {
            Err("the page's Argon2 build gives another tag".to_owned())
        }
    }

    fn sizes(&self) -> ComponentOutcome {
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
        let mut check = NativeArgon2Check::default();
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        assert_eq!((check.id(), check.label()), ("argon2", "Argon2id"));
        assert!(check.runs_at(Tier::Startup));
    }

    #[test]
    fn a_corrupted_tag_fails() {
        let mut small = NativeArgon2Check::default();
        small.0.small.tag[31] ^= 1;
        assert_eq!(
            small.run(Tier::Startup),
            ComponentOutcome::Failed(format!(
                "{} gives another tag for the 1 MiB vector",
                cores()[0].1
            ))
        );
        let mut rfc = NativeArgon2Check::default();
        rfc.0.rfc_tag[0] ^= 0x80;
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
        let mut check = NativeArgon2Check::default();
        check.0.call = two_lanes;
        assert!(check.run(Tier::Startup).is_failure());
    }

    #[test]
    fn a_failing_call_is_told_apart_from_a_wrong_tag() {
        fn refused(_: &Argon2Inputs<'_>, _: &mut WorkArea, _: &mut [u8]) -> Result<(), MhfeError> {
            Err(MhfeError::Argon2("Threading failure".to_owned()))
        }
        let mut check = NativeArgon2Check::default();
        check.0.call = refused;
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
            let mut check = NativeArgon2Check::default();
            check.0.call = call;
            assert_eq!(check.run(Tier::Startup), refused);
            let mut sizes = NativeArgon2SizesCheck::default();
            sizes.0.call = call;
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
        let mut check = NativeArgon2Check::default();
        check.0.call = leaves_blocks;
        assert!(matches!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(detail) if detail.ends_with("leaves its memory unwiped")
        ));
    }

    #[test]
    fn the_sizes_run_in_the_full_self_test_only() {
        let mut check = NativeArgon2SizesCheck::default();
        assert!(!check.runs_at(Tier::Startup));
        assert!(check.runs_at(Tier::Full));
        assert_eq!(check.run(Tier::Full), ComponentOutcome::Passed);
        check.0.sizes[1].tag[5] ^= 4;
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
        takes_nothing(NativeArgon2Check::default);
        takes_nothing(NativeArgon2SizesCheck::default);
    }
}
