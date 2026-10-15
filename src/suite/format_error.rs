//! Word-count, container-policy and packed-state refusals, independent of cipher execution.
use std::fmt;
/// Why a phrase or state cannot use the requested format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatError {
    /// A phrase length other than 12, 15, 18, 21 or 24 words was selected.
    InvalidWordCount(usize),
    /// A built-in check asked for at a length that has none: only a 12- to 21-word original of a
    /// 24-word container carries one.
    NoBuiltInCheckAtLength(usize),
    /// A same-length container was asked for a 24-word original, which has none: its container
    /// always has 24 words.
    SameLengthNeedsShortPhrase,
    /// A length was chosen for a same-length container, which keeps the length of its original.
    LengthChoiceNotApplicable {
        /// The number of words of the container.
        container_words: usize,
    },
    /// The built-in check was asked for a same-length container, which has none.
    NoBuiltInCheck {
        /// The number of words of the container.
        container_words: usize,
    },
    /// The wallet check was asked for a same-length container, whose phrase is never one drawn to
    /// pass it ([`crate::ContainerFacts::offers_wallet_check`]).
    NoWalletCheck {
        /// The number of words of the container.
        container_words: usize,
    },
    /// Hidden wallets were asked of a same-length container, which opens none
    /// ([`crate::ContainerFacts::opens_hidden_wallets`]).
    NoHiddenWallets {
        /// The number of words of the container.
        container_words: usize,
    },
    /// No built-in check passes where a short length was stated or needed: a wrong password,
    /// setting or container, or a 24-word original.
    VerifierMismatch,
    /// The container's word count belongs to a different suite from the one selected.
    ContainerSuite {
        /// The explicitly selected suite.
        selected: crate::Suite,
        /// The container's actual count.
        actual_words: usize,
    },
    /// A raw entropy length cannot be packed into a valid state.
    PackedEntropyLength(usize),
    /// A raw entropy length cannot be a same-length container.
    SameLengthEntropy(usize),
    /// A state does not have suite 3's fixed size.
    Suite3State(usize),
    /// A state cannot be divided into this geometry's two halves.
    StateGeometry {
        /// The supplied state length in bytes.
        state_bytes: usize,
        /// The expected length of each half.
        half_bytes: usize,
    },
}
impl FormatError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> crate::ErrorCode {
        match self {
            Self::InvalidWordCount(_) => crate::ErrorCode::InvalidWordCount,
            Self::NoBuiltInCheckAtLength(_) => crate::ErrorCode::InvalidWordCount,
            Self::SameLengthNeedsShortPhrase => crate::ErrorCode::SameLengthNeedsShortPhrase,
            Self::LengthChoiceNotApplicable { .. } => crate::ErrorCode::LengthChoiceNotApplicable,
            Self::NoBuiltInCheck { .. } => crate::ErrorCode::NoBuiltInCheck,
            Self::NoWalletCheck { .. } => crate::ErrorCode::NoWalletCheck,
            Self::NoHiddenWallets { .. } => crate::ErrorCode::NoHiddenWallets,
            Self::VerifierMismatch => crate::ErrorCode::VerifierMismatch,
            Self::ContainerSuite { .. } => crate::ErrorCode::InvalidContainer,
            Self::PackedEntropyLength(_) => crate::ErrorCode::InternalError,
            Self::SameLengthEntropy(_) => crate::ErrorCode::InternalError,
            Self::Suite3State(_) => crate::ErrorCode::InternalError,
            Self::StateGeometry { .. } => crate::ErrorCode::InternalError,
        }
    }
    /// The stable machine-readable spelling.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
Self::InvalidWordCount(words) => write!(
                f,
                "the original seed phrase must have {} words, not {words}",
                crate::phrase::word_counts_text()
            ),
Self::NoBuiltInCheckAtLength(words) => write!(
                f,
                "a {words}-word original seed phrase has no built-in check (only {} words have \
                 one); compare it with a receiving address or the master key fingerprint of the \
                 wallet instead",
                crate::text::counts_text(&crate::packing::SHORT_WORD_COUNTS)
            ),
Self::SameLengthNeedsShortPhrase => write!(
                f,
                "a 24-word phrase has no same-length container: its container always has 24 \
                 words. Encrypt it without choosing the same length"
            ),
Self::LengthChoiceNotApplicable { container_words } => write!(
                f,
                "a container of {container_words} words keeps the length of its original seed \
                 phrase, so no length is chosen for it; choosing a length applies only to 24-word \
                 containers"
            ),
Self::NoBuiltInCheck { container_words } => write!(
                f,
                "a container of {container_words} words has no built-in check; compare it with a \
                 receiving address or the master key fingerprint of the wallet instead"
            ),
Self::NoWalletCheck { container_words } => write!(
                f,
                "a container of {container_words} words holds a phrase of its own length, which \
                 has no wallet check; compare it with a receiving address or the master key \
                 fingerprint of the wallet instead"
            ),
Self::NoHiddenWallets { container_words } => write!(
                f,
                "a container of {container_words} words opens no hidden wallets: they are opened \
                 on a 24-word container only, for now"
            ),
Self::VerifierMismatch => write!(
                f,
                "the recovered phrase passes no built-in check: the password, PIM, memory level \
                 or container is probably wrong, or the original seed phrase has 24 words"
            ),
Self::ContainerSuite { selected, actual_words } => {
            write!(f, "the container is not a valid English BIP39 phrase: it has {actual_words} words, but ")?;
            match selected {
                crate::Suite::TwentyFourWords => write!(f, "a 24-word container always has {}", crate::packing::STATE_WORDS),
                crate::Suite::SameLength => write!(f, "a same-length container has {}", crate::text::counts_text(&crate::packing::SHORT_WORD_COUNTS)),
            }
        },
Self::PackedEntropyLength(bytes) => write!(f, "internal error: BIP39 entropy of {bytes} bytes cannot be packed"),
Self::SameLengthEntropy(bytes) => write!(f, "internal error: a same-length container cannot hold {bytes} bytes of entropy"),
Self::Suite3State(bytes) => write!(f, "internal error: a suite 3 state has {} bytes, not {bytes}", crate::packing::STATE_BYTES),
Self::StateGeometry { state_bytes, half_bytes } => write!(f, "internal error: a state of {state_bytes} bytes does not fit halves of {half_bytes} bytes"),
    }
    }
}
impl std::error::Error for FormatError {}
impl crate::ErrorIdentity for FormatError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
