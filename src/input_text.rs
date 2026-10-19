//! A bounded borrowed view for text utilities, before any owned copy or token collection.
//! This raw UTF-8 limit is independent of the cipher password's normalized encoding rules.

/// Why a utility refused raw text, without retaining any of that text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextSizeError {
    /// The raw UTF-8 byte count exceeds [`InputText::MAX_BYTES`].
    TooLong {
        /// The supplied raw byte count.
        bytes: usize,
    },
}

impl TextSizeError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> crate::ErrorCode {
        crate::ErrorCode::InvalidRequest
    }

    /// The machine-readable refusal code.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}

impl std::fmt::Display for TextSizeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self::TooLong { bytes } = self;
        write!(
            formatter,
            "invalid request: the text is {bytes} UTF-8 bytes; at most {} are allowed",
            InputText::MAX_BYTES
        )
    }
}

impl std::error::Error for TextSizeError {}

impl crate::ErrorIdentity for TextSizeError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}

/// Raw utility text that fits the typed-line byte limit; validation never copies or normalizes it.
pub struct InputText<'a>(&'a str);

impl std::fmt::Debug for InputText<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InputText(hidden)")
    }
}

impl<'a> InputText<'a> {
    /// The same raw-byte capacity used for native typed lines.
    pub const MAX_BYTES: usize = crate::memory::TYPED_LINE_BYTES;

    /// Refuses oversized text before an owning buffer is made. Empty text is permitted.
    pub fn read(text: &'a str) -> Result<Self, TextSizeError> {
        Self::require_size(text.len())?;
        Ok(Self(text))
    }

    /// Checks an outside byte length before decoding, scanning or copying the supplied text.
    pub fn require_size(bytes: usize) -> Result<(), TextSizeError> {
        if bytes > Self::MAX_BYTES {
            return Err(TextSizeError::TooLong { bytes });
        }
        Ok(())
    }

    /// The original text, borrowed without normalization or truncation.
    pub fn text(&self) -> &'a str {
        self.0
    }
}
