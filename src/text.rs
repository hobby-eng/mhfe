//! Small stateless display helpers shared by independent modules. They depend on no wallet,
//! cipher, checker or front end; each caller owns the data and chooses its message.

/// A count displayed with groups of thousands: "65,536". The library and every front end use
/// this value's display contract instead of choosing separators themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupedCount(u128);

impl GroupedCount {
    /// The unsigned count to display, without rounding or changing its units.
    pub fn new(count: impl Into<u128>) -> Self {
        Self(count.into())
    }
}

impl std::fmt::Display for GroupedCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&grouped(self.0))
    }
}

/// The shared implementation of the count display contract.
pub(crate) fn grouped(count: impl Into<u128>) -> String {
    let digits = count.into().to_string();
    let mut text = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            text.push(',');
        }
        text.push(digit);
    }
    text
}

/// Word counts as a message lists them, the last after "or": "12, 15, 18 or 21".
pub(crate) fn counts_text(counts: &[usize]) -> String {
    let counts: Vec<String> = counts.iter().map(ToString::to_string).collect();
    match counts.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        Some((last, _)) => last.clone(),
        None => String::new(),
    }
}

/// A memory size as every front end writes it: whole tebibytes from 1 TiB on, as the highest
/// levels are, else gibibytes with one decimal unless whole: "2 GiB", "1.5 GiB", "3 TiB". Integers
/// only.
pub(crate) fn memory_text(bytes: u64) -> String {
    const GIB: u64 = 1 << 30;
    const TIB: u64 = 1 << 40;
    if bytes >= TIB && bytes.is_multiple_of(TIB) {
        return format!("{} TiB", bytes / TIB);
    }
    if bytes.is_multiple_of(GIB) {
        return format!("{} GiB", bytes / GIB);
    }
    let tenths = bytes / (GIB / 10);
    format!("{}.{} GiB", tenths / 10, tenths % 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_are_grouped_by_thousands() {
        assert_eq!(grouped(0u32), "0");
        assert_eq!(grouped(999u32), "999");
        assert_eq!(grouped(1_000u32), "1,000");
        assert_eq!(grouped(65_536u32), "65,536");
        assert_eq!(grouped(1_234_567u32), "1,234,567");
        assert_eq!(grouped(1u128 << 64), "18,446,744,073,709,551,616");
    }
}
