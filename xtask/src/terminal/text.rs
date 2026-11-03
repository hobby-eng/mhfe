//! What a terminal shows of the tool's output: its text without control sequences or the rows of
//! hints below a typed line, its lines after carriage returns, and running text wrapped as mhfe
//! wraps it.

/// `output` without the terminal's control sequences, ESC [ then digits, `;` or `?`, then a
/// letter.
pub(crate) fn without_controls(output: &[u8]) -> Vec<u8> {
    let mut text = Vec::with_capacity(output.len());
    let mut at = 0;
    while at < output.len() {
        match control_end(output, at) {
            Some(end) => at = end,
            None => {
                text.push(output[at]);
                at += 1;
            }
        }
    }
    text
}

/// Where the control sequence at `at` ends, if one starts there.
fn control_end(output: &[u8], at: usize) -> Option<usize> {
    let rest = output.get(at..)?.strip_prefix(b"\x1b[")?;
    let parameters = rest
        .iter()
        .take_while(|byte| byte.is_ascii_digit() || matches!(byte, b';' | b'?'))
        .count();
    rest.get(parameters)
        .filter(|byte| byte.is_ascii_alphabetic())
        .map(|_| at + 2 + parameters + 1)
}

/// The length of a colour code (ESC [ digits or `;`, then `m`) at the start of `bytes`.
fn colour_code(bytes: &[u8]) -> Option<usize> {
    let rest = bytes.strip_prefix(b"\x1b[")?;
    let parameters = rest
        .iter()
        .take_while(|byte| byte.is_ascii_digit() || **byte == b';')
        .count();
    (rest.get(parameters) == Some(&b'm')).then_some(2 + parameters + 1)
}

/// Whether `output` holds a colour code.
pub(crate) fn has_colour(output: &[u8]) -> bool {
    (0..output.len()).any(|at| output[at] == 0x1b && colour_code(&output[at..]).is_some())
}

/// `output` without the rows of hints below a line being typed (typed_line.rs in the tool): each
/// written after the line's "clear below" on a row of its own, in colour or not, before the
/// cursor moves back up. Nothing else is taken out.
pub(crate) fn without_hints(output: &[u8]) -> Vec<u8> {
    const CLEAR_BELOW: &[u8] = b"\x1b[J";
    let mut text = Vec::with_capacity(output.len());
    let mut at = 0;
    while at < output.len() {
        if output[at..].starts_with(CLEAR_BELOW) {
            text.extend_from_slice(CLEAR_BELOW);
            at += CLEAR_BELOW.len();
            if let Some(end) = hint_rows_end(output, at) {
                at = end;
            }
        } else {
            text.push(output[at]);
            at += 1;
        }
    }
    text
}

/// Where the hint rows that start at `start` end: one or more rows, each a line break (after
/// one more carriage return, perhaps) and text or colour codes, followed by a cursor move up.
fn hint_rows_end(output: &[u8], start: usize) -> Option<usize> {
    let mut end = start;
    let mut rows = 0;
    loop {
        let rest = &output[end..];
        let mut at = if rest.starts_with(b"\r\r\n") {
            end + 3
        } else if rest.starts_with(b"\r\n") {
            end + 2
        } else {
            break;
        };
        while at < output.len() {
            if output[at] != 0x1b {
                at += 1;
            } else if let Some(length) = colour_code(&output[at..]) {
                at += length;
            } else {
                break;
            }
        }
        end = at;
        rows += 1;
    }
    let up = output.get(end..)?.strip_prefix(b"\x1b[")?;
    let digits = up.iter().take_while(|byte| byte.is_ascii_digit()).count();
    (rows > 0 && digits > 0 && up.get(digits) == Some(&b'A')).then_some(end)
}

/// The characters a line showed as they were typed: without the hint rows below it, the space
/// and backspace that move the cursor to the next row, and the control sequences.
pub(crate) fn typed_echo(output: &[u8]) -> Vec<u8> {
    let hintless = without_hints(output);
    let mut moved = Vec::with_capacity(hintless.len());
    let mut at = 0;
    while at < hintless.len() {
        if hintless[at..].starts_with(b" \x08") {
            at += 2;
        } else {
            moved.push(hintless[at]);
            at += 1;
        }
    }
    without_controls(&moved)
}

/// The lines a terminal shows for `output`, which holds no control sequences: a carriage return
/// alone goes back to the start of its line, and what follows is written over what stood there.
pub(crate) fn screen_lines(output: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(output)
        .split("\r\n")
        .map(|line| {
            let mut shown: Vec<char> = Vec::new();
            for part in line.split('\r') {
                for (index, char) in part.chars().enumerate() {
                    match shown.get_mut(index) {
                        Some(place) => *place = char,
                        None => shown.push(char),
                    }
                }
            }
            shown.into_iter().collect::<String>().trim_end().to_owned()
        })
        .collect()
}

/// `text` broken into lines of at most `width` characters at its spaces, as mhfe wraps running
/// text (wrap in src/bin/mhfe/style.rs); a longer word stays whole on a line of its own.
pub(crate) fn wrapped(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// `bytes` with every run of whitespace made one space.
pub(crate) fn words(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_rows_are_taken_out_and_nothing_else() {
        let output = b"abc\x1b[J\r\n\x1b[90m136 words\x1b[0m\x1b[1Ad\x1b[J\r\nno move";
        assert_eq!(
            without_hints(output),
            b"abc\x1b[J\x1b[1Ad\x1b[J\r\nno move".to_vec()
        );
    }

    #[test]
    fn control_sequences_are_taken_out() {
        assert_eq!(
            without_controls(b"\x1b[?1049ha\x1b[2Jb\x1b[1;5Ac"),
            b"abc".to_vec()
        );
    }

    #[test]
    fn a_carriage_return_writes_over_its_line() {
        assert_eq!(
            screen_lines(b"Testing x\r  Done\r\nnext"),
            ["  Doneg x", "next"]
        );
    }

    #[test]
    fn text_wraps_at_spaces() {
        assert_eq!(wrapped("one two three", 7), ["one two", "three"]);
        assert_eq!(wrapped("averylongword x", 4), ["averylongword", "x"]);
    }
}
