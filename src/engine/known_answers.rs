//! Known answers of the Argon2id engine: the self-checks `argon2` (startup) and `argon2-sizes`
//! (full self-test only).
//!
//! The checks are closed. Their inputs are private constants, they take no cost and no password,
//! and they give only an outcome, so that they add no way to Argon2 at another cost. An engine
//! takes its cost with every call, and every operation asks for the cost of its work factor; the
//! one engine that runs below the cost it is asked for is a test engine, in no release build
//! (scripts/check-release-artifacts.sh looks for its marker). Natively they run the C code of
//! mhfe-core on this processor, on the copy of its core that an operation runs here. In a browser
//! they run the page's Emscripten build of the same code through the bridge every operation uses.

#[cfg(not(target_arch = "wasm32"))]
use mhfe_core::{Argon2Engine, NativeArgon2};

#[cfg(not(target_arch = "wasm32"))]
use super::error_of;
use super::{Argon2Cost, KEY_BYTES, SALT_BYTES};
use crate::self_check::{hex, ComponentCheck, ComponentOutcome, Tier};
use crate::MhfeError;

/// The public password and salt of the known answers below, the inputs that
/// `cargo xtask package-check` gives both Emscripten builds too.
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
/// independent of the reference C code (knownTags in xtask/pages/package/checks/core.js).
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

/// What a call that returned an error tells: the message of an Argon2 failure, which names no
/// input, else the error code.
fn could_not_run(error: &MhfeError) -> String {
    match error {
        MhfeError::Argon2(message) => format!("Argon2id could not run: {message}"),
        other => format!("Argon2id could not run: {}", other.code()),
    }
}

/// What a build of Argon2 answers its known answers with: the native engine, or a page's Emscripten
/// build through the bridge. The two parts of a self-check below ask it, so that both builds report
/// under the same ids, labels and tiers.
trait Argon2Answers {
    /// The known answer at 1 MiB: `Err` names what went wrong.
    fn small(&self) -> Result<(), String>;
    /// The known answers at 64 and 256 MiB, with a size the computer cannot give told apart.
    fn sizes(&self) -> ComponentOutcome;
}

/// The outcome of the known answers of `sizes`, each of which `call` computes. `refusal` says that
/// a size of memory could not be had, and `build` names what gave another tag.
fn compare_sizes(
    sizes: [KnownTag; 2],
    refusal: &str,
    build: &str,
    mut call: impl FnMut(Argon2Cost, &mut [u8; KEY_BYTES]) -> Result<(), MhfeError>,
) -> ComponentOutcome {
    for size in sizes {
        let mut tag = [0u8; KEY_BYTES];
        match call(size.cost, &mut tag) {
            Err(MhfeError::MemoryAllocation { .. }) => {
                return ComponentOutcome::NotAvailable(format!(
                    "{refusal} {} MiB",
                    size.mebibytes()
                ))
            }
            Err(error) => return ComponentOutcome::Failed(could_not_run(&error)),
            Ok(()) if tag != size.tag => {
                return ComponentOutcome::Failed(format!(
                    "{build} gives another tag at {} MiB",
                    size.mebibytes()
                ))
            }
            Ok(()) => {}
        }
    }
    ComponentOutcome::Passed
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

/// One known-answer call at a cost: [`reserved_call`], or a stand-in in the tests of these checks.
#[cfg(not(target_arch = "wasm32"))]
type Call = fn(Argon2Cost, &mut [u8; KEY_BYTES]) -> Result<(), MhfeError>;

/// The known answers of the native Argon2id engine, which `call` computes.
///
/// At startup ([`NativeArgon2Check`]) a call shaped as MHFE makes it at 1 MiB (four lanes on four
/// threads, version 1.3, no secret or associated data). About a millisecond. It starts four threads
/// and joins them before it returns: the command-line tool runs it after a command has entered its
/// own network namespace, which needs a process of a single thread, and before the start menu
/// opens, which enters none.
///
/// In the full self-test ([`NativeArgon2SizesCheck`]), the same at 64 and 256 MiB: indexing over
/// many segments. About a quarter of a second and 256 MiB. A computer that cannot reserve the
/// memory is told apart from a wrong answer: that part is not available here, rather than failed.
#[cfg(not(target_arch = "wasm32"))]
pub struct NativeAnswers {
    small: KnownTag,
    sizes: [KnownTag; 2],
    call: Call,
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for NativeAnswers {
    fn default() -> Self {
        Self {
            small: SMALL,
            sizes: SIZES,
            call: reserved_call,
        }
    }
}

/// The startup part `argon2` of the native engine.
#[cfg(not(target_arch = "wasm32"))]
pub type NativeArgon2Check = Argon2Check<NativeAnswers>;
/// The full self-test's part `argon2-sizes` of the native engine.
#[cfg(not(target_arch = "wasm32"))]
pub type NativeArgon2SizesCheck = Argon2SizesCheck<NativeAnswers>;

/// The native engine's tag of [`PASSWORD`] and [`SALT`] at `cost`, in a work area of that size.
#[cfg(not(target_arch = "wasm32"))]
fn reserved_call(cost: Argon2Cost, tag: &mut [u8; KEY_BYTES]) -> Result<(), MhfeError> {
    let refusal = |error| error_of(error, cost.memory_bytes());
    let mut engine = NativeArgon2::new(cost.memory_kib).map_err(refusal)?;
    engine
        .argon2id(PASSWORD, SALT, cost.memory_kib, cost.passes, tag)
        .map_err(refusal)
}

#[cfg(not(target_arch = "wasm32"))]
impl Argon2Answers for NativeAnswers {
    fn small(&self) -> Result<(), String> {
        let mut tag = [0u8; KEY_BYTES];
        (self.call)(self.small.cost, &mut tag).map_err(|error| could_not_run(&error))?;
        if tag == self.small.tag {
            Ok(())
        } else {
            Err("the Argon2 core gives another tag for the 1 MiB vector".to_owned())
        }
    }

    fn sizes(&self) -> ComponentOutcome {
        compare_sizes(
            self.sizes,
            "the computer could not reserve",
            "the Argon2 core",
            self.call,
        )
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
        compare_sizes(
            SIZES,
            "the browser could not give",
            "the page's Argon2 build",
            |cost, tag| derive_with(self.argon2, PASSWORD, SALT, cost, tag),
        )
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
        // Fault: the expected tag, damaged as by a broken build or faulty memory.
        let mut small = NativeArgon2Check::default();
        small.0.small.tag[31] ^= 1;
        assert_eq!(
            small.run(Tier::Startup),
            ComponentOutcome::Failed(
                "the Argon2 core gives another tag for the 1 MiB vector".to_owned()
            )
        );
    }

    #[test]
    fn a_failing_call_is_told_apart_from_a_wrong_tag() {
        fn refused(_: Argon2Cost, _: &mut [u8; KEY_BYTES]) -> Result<(), MhfeError> {
            Err(MhfeError::Argon2(
                "the reference code returned error -33".to_owned(),
            ))
        }
        // Fault: an Argon2 call that fails, as when the system refuses its threads.
        let mut check = NativeArgon2Check::default();
        check.0.call = refused;
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(
                "Argon2id could not run: the reference code returned error -33".to_owned()
            )
        );
    }

    #[test]
    fn a_size_the_computer_cannot_give_is_not_available_rather_than_failed() {
        fn refused(cost: Argon2Cost, _: &mut [u8; KEY_BYTES]) -> Result<(), MhfeError> {
            Err(MhfeError::MemoryAllocation {
                bytes: cost.memory_bytes(),
            })
        }
        // Fault: a reservation the system refuses.
        let mut sizes = NativeArgon2SizesCheck::default();
        sizes.0.call = refused;
        assert_eq!(
            sizes.run(Tier::Full),
            ComponentOutcome::NotAvailable("the computer could not reserve 64 MiB".to_owned())
        );
    }

    #[test]
    fn the_sizes_run_in_the_full_self_test_only() {
        let mut check = NativeArgon2SizesCheck::default();
        assert!(!check.runs_at(Tier::Startup));
        assert!(check.runs_at(Tier::Full));
        assert_eq!(check.run(Tier::Full), ComponentOutcome::Passed);
        // Fault: the expected 256 MiB tag, damaged as by a broken build or faulty memory.
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
