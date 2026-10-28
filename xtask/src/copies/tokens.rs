//! The tokens of Rust and JavaScript source text, for the copies gate: white space and comments
//! left out, words and numbers whole, every string, character, template and regular expression
//! as one token, and every other character as a token of its own, each with the line it starts
//! on. Not a full parser of either language, but the same code always gives the same tokens,
//! which is all that finding copies needs. In Rust it reads nested block comments, raw, byte and
//! C strings, and lifetimes told apart from characters, and it leaves out the `use` lists; in
//! JavaScript it leaves out the import and export lists. It also gives the lines on which a
//! comment marks a deliberate copy: only a comment marks one, never a string that holds the
//! words.

use std::collections::HashSet;
use std::iter;

/// The marker of a deliberate copy, in a comment, in any case.
const DELIBERATE: &str = "deliberate copy";
/// The tokens after which a statement starts.
const STATEMENT_ENDS: [&str; 3] = [";", "{", "}"];
/// The most tokens a `use`, import or export list may have; a longer one is read as code.
const MOST_LIST_TOKENS: usize = 1024;
/// After these JavaScript tokens a slash starts a regular expression, not a division.
const BEFORE_REGEX: [&str; 33] = [
    "(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%", "<", ">", "~",
    "^", "return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw",
    "yield", "await",
];

/// A token: its text, and the line it starts on, counted from 1.
#[derive(Clone)]
pub(super) struct Token {
    pub(super) key: String,
    pub(super) line: usize,
}

/// The tokens of a text without its import and export lists (`use` lists in Rust), and the lines
/// on which a comment marks a deliberate copy.
pub(super) struct Tokens {
    pub(super) tokens: Vec<Token>,
    pub(super) marked_lines: HashSet<usize>,
}

/// What a piece of the text is.
enum Kind {
    Space,
    Comment,
    Token,
}

/// The language of a source file.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Language {
    Rust,
    JavaScript,
}

impl Language {
    /// The language of the file at `path`: Rust for `.rs`, JavaScript otherwise (TypeScript's
    /// declarations read as JavaScript).
    pub(super) fn of(path: &str) -> Self {
        if path.ends_with(".rs") {
            Self::Rust
        } else {
            Self::JavaScript
        }
    }
}

/// Reads `text`, written in `language`.
pub(super) fn read(text: &str, language: Language) -> Tokens {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut marked_lines = HashSet::new();
    let (mut at, mut line) = (0, 1);
    while at < chars.len() {
        let previous = tokens.last().map(|token: &Token| token.key.as_str());
        let (kind, length) = piece(&chars[at..], language, previous);
        // A string or a comment left open runs to the end of the text.
        let end = chars.len().min(at + length);
        let body = &chars[at..end];
        let newlines = body.iter().filter(|&&char| char == '\n').count();
        match kind {
            // Every line of the comment, so that its last line counts as the line above the copy.
            Kind::Comment if marks_copy(body) => marked_lines.extend(line..=line + newlines),
            Kind::Token => tokens.push(Token {
                key: body.iter().collect(),
                line,
            }),
            Kind::Space | Kind::Comment => {}
        }
        line += newlines;
        at = end;
    }
    Tokens {
        tokens: without_lists(&tokens, language),
        marked_lines,
    }
}

/// Whether `comment` says that the code under it is a deliberate copy.
fn marks_copy(comment: &[char]) -> bool {
    comment
        .iter()
        .collect::<String>()
        .to_lowercase()
        .contains(DELIBERATE)
}

/// The kind and the length of the piece that starts `rest`, which is not empty, after the token
/// `previous`.
fn piece(rest: &[char], language: Language, previous: Option<&str>) -> (Kind, usize) {
    if rest.first().is_some_and(|char| char.is_whitespace()) {
        (Kind::Space, 1)
    } else if rest.starts_with(&['/', '/']) {
        (
            Kind::Comment,
            rest.iter().take_while(|&&char| char != '\n').count(),
        )
    } else if rest.starts_with(&['/', '*']) {
        (Kind::Comment, block_comment_length(rest, language))
    } else {
        (Kind::Token, token_length(rest, language, previous))
    }
}

/// The length of the block comment that starts `rest`: in Rust with the comments nested in it, in
/// JavaScript as far as the first `*/`.
fn block_comment_length(rest: &[char], language: Language) -> usize {
    if language == Language::JavaScript {
        let close = rest[2..].windows(2).position(|pair| pair == ['*', '/']);
        return close.map_or(rest.len(), |close| close + 4);
    }
    let (mut at, mut depth) = (0, 0);
    while at < rest.len() {
        if rest[at..].starts_with(&['/', '*']) {
            depth += 1;
            at += 2;
        } else if rest[at..].starts_with(&['*', '/']) {
            depth -= 1;
            at += 2;
            if depth == 0 {
                break;
            }
        } else {
            at += 1;
        }
    }
    at
}

/// The length of the token that starts `rest`, after the token `previous`: a string, a character,
/// a template or a regular expression whole, a word or a number whole, or any other character
/// alone.
fn token_length(rest: &[char], language: Language, previous: Option<&str>) -> usize {
    let first = rest.first().copied().unwrap_or_default();
    let javascript = language == Language::JavaScript;
    if !javascript && let Some(length) = rust_literal_length(rest) {
        length
    } else if first.is_alphabetic() || matches!(first, '_' | '$') {
        rest.iter()
            .take_while(|char| char.is_alphanumeric() || matches!(char, '_' | '$'))
            .count()
    } else if first.is_ascii_digit() {
        number_length(rest)
    } else if first == '"' || (javascript && first == '\'') {
        quoted_length(rest)
    } else if javascript && first == '`' {
        template_length(rest)
    } else if javascript && first == '/' && previous.is_none_or(|key| BEFORE_REGEX.contains(&key)) {
        regex_length(rest)
    } else {
        1
    }
}

/// The length of the Rust raw, byte or C string or the byte or character that starts `rest`, or
/// of the lifetime or label its quote starts, or None when none of them starts there.
fn rust_literal_length(rest: &[char]) -> Option<usize> {
    let first = rest.first().copied().unwrap_or_default();
    let after = rest.get(1..).unwrap_or_default();
    if let Some(length) = raw_string_length(rest) {
        Some(length)
    } else if matches!(first, 'b' | 'c') && after.first() == Some(&'"') {
        Some(1 + quoted_length(after))
    } else if first == 'b'
        && let Some(length) = char_length(after)
    {
        Some(1 + length)
    } else if first == '\'' {
        // A character, or a lifetime or a label: the quote and its name.
        Some(char_length(rest).unwrap_or_else(|| {
            1 + after
                .iter()
                .take_while(|char| char.is_alphanumeric() || **char == '_')
                .count()
        }))
    } else {
        None
    }
}

/// The length of the raw string that starts `rest` (r"…", r#"…"#, br##"…"##, cr"…"), as far as
/// its closing quote and hashes, or None when none starts there.
fn raw_string_length(rest: &[char]) -> Option<usize> {
    let prefix = usize::from(matches!(rest.first(), Some('b' | 'c')));
    let hashes = rest
        .iter()
        .skip(prefix + 1)
        .take_while(|&&char| char == '#')
        .count();
    let opening = prefix + hashes + 2;
    if rest.get(prefix) != Some(&'r') || rest.get(opening - 1) != Some(&'"') {
        return None;
    }
    let closing: Vec<char> = iter::once('"').chain(iter::repeat_n('#', hashes)).collect();
    let body = rest.get(opening..).unwrap_or_default();
    let close = body
        .windows(closing.len())
        .position(|window| window == closing.as_slice());
    Some(close.map_or(rest.len(), |close| opening + close + closing.len()))
}

/// The length of the string whose opening quote starts `rest`, as far as the same quote that closes
/// it; a backslash takes the character after it.
fn quoted_length(rest: &[char]) -> usize {
    let quote = rest.first().copied();
    let mut at = 1;
    while let Some(&char) = rest.get(at)
        && Some(char) != quote
    {
        at += if char == '\\' { 2 } else { 1 };
    }
    at + 1
}

/// The length of the JavaScript template whose backtick starts `rest`, its `${…}` expressions
/// included, as far as the backtick that closes it.
fn template_length(rest: &[char]) -> usize {
    let (mut at, mut depth) = (1, 0);
    while let Some(&char) = rest.get(at)
        && (char != '`' || depth > 0)
    {
        if char == '\\' {
            at += 1;
        } else if rest[at..].starts_with(&['$', '{']) {
            depth += 1;
        } else if char == '}' && depth > 0 {
            depth -= 1;
        }
        at += 1;
    }
    at + 1
}

/// The length of the JavaScript regular expression whose slash starts `rest`, its flags included:
/// as far as the slash that closes it outside a character class, or the end of the line.
fn regex_length(rest: &[char]) -> usize {
    let (mut at, mut class) = (1, false);
    while let Some(&char) = rest.get(at)
        && (char != '/' || class)
        && char != '\n'
    {
        if char == '\\' {
            at += 1;
        } else if char == '[' {
            class = true;
        } else if char == ']' {
            class = false;
        }
        at += 1;
    }
    let flags = rest
        .iter()
        .skip(at + 1)
        .take_while(|char| char.is_ascii_lowercase())
        .count();
    at + 1 + flags
}

/// The length of the character that starts `rest` ('a', '\n', '\'', '\x41', '\u{1F600}'), or
/// None when its quote starts a lifetime or a label. The forms of an escape are tried in turn:
/// `\u{…}`, `\x` with two digits, then any one character but a line break.
fn char_length(rest: &[char]) -> Option<usize> {
    let at = |index: usize| rest.get(index).copied();
    let closed = |end: usize| (at(end) == Some('\'')).then_some(end + 1);
    if at(0) != Some('\'') {
        return None;
    }
    if at(1) != Some('\\') {
        return at(1)
            .filter(|char| !matches!(char, '\'' | '\n'))
            .and_then(|_| closed(2));
    }
    let digits = rest
        .iter()
        .skip(4)
        .take_while(|char| char.is_ascii_hexdigit() || **char == '_')
        .count();
    let unicode = (at(2) == Some('u') && at(3) == Some('{') && digits > 0)
        .then_some(4 + digits)
        .filter(|&brace| at(brace) == Some('}'))
        .map(|brace| brace + 1);
    let hex_digit = |index: usize| at(index).is_some_and(|char| char.is_ascii_hexdigit());
    let hex = (at(2) == Some('x') && hex_digit(3) && hex_digit(4)).then_some(5);
    let any = at(2)
        .filter(|char| !matches!(char, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
        .map(|_| 3);
    [unicode, hex, any].into_iter().flatten().find_map(closed)
}

/// The length of the number that starts `rest`, its suffix and fraction included, but not the
/// `..` of a range after it.
fn number_length(rest: &[char]) -> usize {
    let ends = |at: usize| {
        let char = rest[at];
        !(char.is_ascii_alphanumeric() || matches!(char, '_' | '.'))
            || rest[at..].starts_with(&['.', '.'])
    };
    (0..rest.len()).find(|&at| ends(at)).unwrap_or(rest.len())
}

/// `tokens` without the `use` lists of Rust or the import and export lists of JavaScript: two
/// files that use the same modules share no code.
fn without_lists(tokens: &[Token], language: Language) -> Vec<Token> {
    let list_end: fn(&[Token], usize) -> Option<usize> = match language {
        Language::Rust => use_list_end,
        Language::JavaScript => import_list_end,
    };
    let mut kept = Vec::with_capacity(tokens.len());
    let mut at = 0;
    while let Some(token) = tokens.get(at) {
        if let Some(end) = list_end(tokens, at) {
            at = end;
        } else {
            kept.push(token.clone());
            at += 1;
        }
    }
    kept
}

/// Where the `use` list starting at `at` ends, the index after its semicolon, or None when none
/// starts there. A `use` at the start of a statement, `pub use` and `pub(crate) use` included,
/// runs to its semicolon; a `use` inside a type, as in `impl Trait + use<'a>`, is code.
fn use_list_end(tokens: &[Token], at: usize) -> Option<usize> {
    let key = |index: usize| tokens.get(index).map(|token| token.key.as_str());
    let before = |count: usize| at.checked_sub(count).and_then(key);
    if key(at) != Some("use") {
        return None;
    }
    let from = if before(1) == Some("pub") {
        at - 1
    } else if before(1) == Some(")") && before(4) == Some("pub") {
        at - 4
    } else {
        at
    };
    if !starts_statement(tokens, from, Language::Rust) {
        return None;
    }
    let last = tokens.len().min(at + MOST_LIST_TOKENS);
    (at + 1..last)
        .find(|&end| key(end) == Some(";"))
        .map(|end| end + 1)
}

/// Whether the token at `at` starts a statement: the first one, or one after a token of
/// `STATEMENT_ENDS` or, in Rust, after the `]` that ends an attribute, as in `#[cfg(test)] use …;`.
fn starts_statement(tokens: &[Token], at: usize, language: Language) -> bool {
    at.checked_sub(1)
        .and_then(|index| tokens.get(index))
        .is_none_or(|token| {
            STATEMENT_ENDS.contains(&token.key.as_str())
                || (language == Language::Rust && token.key == "]")
        })
}

/// Where the JavaScript import or export list starting at `at` ends, the index after its last
/// token, or None when none starts there. `import` and `export { … }`, `export type { … }` and
/// `export * …` lists at the start of a statement end after their `from "…"`, or for a local
/// `export { … }` after its brace, with the semicolon if there is one: a list without one
/// (automatic semicolon insertion) ends there too, so that the code after it is read.
/// `import(…)`, `import.meta` and exported declarations (`export function`, `export class`, …)
/// are code.
fn import_list_end(tokens: &[Token], at: usize) -> Option<usize> {
    if !starts_statement(tokens, at, Language::JavaScript) {
        return None;
    }
    let key = |index: usize| tokens.get(index).map(|token| token.key.as_str());
    let (first, next) = (key(at)?, key(at + 1));
    let list = match first {
        "import" => !matches!(next, Some("(" | ".")),
        "export" => {
            matches!(next, Some("{" | "*")) || (next == Some("type") && key(at + 2) == Some("{"))
        }
        _ => false,
    };
    if !list {
        return None;
    }
    let with_semicolon = |end: usize| if key(end) == Some(";") { end + 1 } else { end };
    let string = |index: usize| key(index).is_some_and(|token| token.starts_with(['"', '\'', '`']));
    if first == "import" && string(at + 1) {
        return Some(with_semicolon(at + 2));
    }
    let mut depth = 0_isize;
    for end in at + 1..tokens.len().min(at + MOST_LIST_TOKENS) {
        match key(end) {
            Some("{") => depth += 1,
            Some("}") => {
                depth -= 1;
                if depth == 0 && first == "export" && key(end + 1) != Some("from") {
                    return Some(with_semicolon(end + 1));
                }
            }
            Some("from") if depth == 0 && string(end + 1) => return Some(with_semicolon(end + 2)),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(text: &str) -> Vec<String> {
        keys_of(text, Language::Rust)
    }

    fn keys_of(text: &str, language: Language) -> Vec<String> {
        read(text, language)
            .tokens
            .into_iter()
            .map(|token| token.key)
            .collect()
    }

    #[test]
    fn comments_are_left_out_and_a_nested_block_comment_ends_with_its_outer_one() {
        assert_eq!(keys("/* a /* b */ c */ x // y\nz /**/ w"), ["x", "z", "w"]);
    }

    #[test]
    fn a_character_is_one_token_and_a_lifetime_or_label_is_its_quote_and_name() {
        let text = r"'a' '\'' '\\' '\x41' '\u{1F600}' b'x' &'a str 'outer: loop";
        let expected = [
            r"'a'",
            r"'\''",
            r"'\\'",
            r"'\x41'",
            r"'\u{1F600}'",
            "b'x'",
            "&",
            "'a",
            "str",
        ];
        assert_eq!(keys(text)[..expected.len()], expected);
        assert_eq!(keys(text)[expected.len()..], ["'outer", ":", "loop"]);
    }

    #[test]
    fn strings_of_every_kind_are_one_token() {
        let text = r####""a\"b" r#"a"b"# br##"c"#d"## b"e" c"f" cr"g""####;
        let expected = [
            r#""a\"b""#,
            r##"r#"a"b"#"##,
            r###"br##"c"#d"##"###,
            r#"b"e""#,
            r#"c"f""#,
            r#"cr"g""#,
        ];
        assert_eq!(keys(text), expected);
    }

    #[test]
    fn a_number_is_whole_but_the_range_after_it_is_not_part_of_it() {
        assert_eq!(
            keys("1.5e3 0x_ffu8 1..2"),
            ["1.5e3", "0x_ffu8", "1", ".", ".", "2"]
        );
    }

    #[test]
    fn a_string_or_comment_left_open_runs_to_the_end_of_the_text() {
        assert_eq!(keys("x \"open"), ["x", "\"open"]);
        assert_eq!(keys("x r#\"open\" y"), ["x", "r#\"open\" y"]);
        assert_eq!(keys("x /* open /* */ y"), ["x"]);
    }

    #[test]
    fn every_token_keeps_the_line_it_starts_on() {
        let text = "a r\"one\ntwo\" b\n/* three\nfour */ c\n// five\nd";
        let lines: Vec<(String, usize)> = read(text, Language::Rust)
            .tokens
            .into_iter()
            .map(|token| (token.key, token.line))
            .collect();
        let expected = [("a", 1), ("r\"one\ntwo\"", 1), ("b", 2), ("c", 4), ("d", 6)];
        let expected: Vec<(String, usize)> = expected
            .iter()
            .map(|&(key, line)| (key.to_owned(), line))
            .collect();
        assert_eq!(lines, expected);
    }

    #[test]
    fn use_lists_are_left_out_but_a_use_in_a_type_is_code() {
        let text = "use a::b;\npub use c::{d, e};\npub(crate) use f::g;\n#[cfg(test)]\nuse h;\n\
                    fn f() { use i::j; k }\nfn l() -> impl Sized + use<'m> {}";
        // The visibility before a list stays: a few tokens, which never make a copy alone.
        let expected = [
            "pub", "pub", "(", "crate", ")", "#", "[", "cfg", "(", "test", ")", "]", "fn", "f",
            "(", ")", "{", "k", "}", "fn", "l", "(", ")", "-", ">", "impl", "Sized", "+", "use",
            "<", "'m", ">", "{", "}",
        ];
        assert_eq!(keys(text), expected);
    }

    #[test]
    fn a_comment_marks_its_lines_in_any_case_and_a_string_marks_none() {
        let text = "x\n/* A DELIBERATE COPY:\n its reason. */\nlet s = \"deliberate copy\";\n\
                    // deliberate copy\ny";
        let mut marked: Vec<usize> = read(text, Language::Rust)
            .marked_lines
            .into_iter()
            .collect();
        marked.sort_unstable();
        assert_eq!(marked, [2, 3, 5]);
    }

    #[test]
    fn javascript_strings_templates_and_regular_expressions_are_one_token() {
        let text = r#"'a\'b' "c" `d${ {e: `f`} }g` x = /[/]\//gu; y / z / w"#;
        let expected = [
            r"'a\'b'",
            r#""c""#,
            "`d${ {e: `f`} }g`",
            "x",
            "=",
            r"/[/]\//gu",
            ";",
            "y",
            "/",
            "z",
            "/",
            "w",
        ];
        assert_eq!(keys_of(text, Language::JavaScript), expected);
    }

    #[test]
    fn a_javascript_block_comment_ends_at_its_first_close_and_a_text_may_start_with_a_regex() {
        assert_eq!(
            keys_of("/a/ /* b /* c */ d */", Language::JavaScript),
            ["/a/", "d", "*", "/"]
        );
    }

    #[test]
    fn javascript_lists_are_left_out_but_import_calls_and_exported_declarations_are_code() {
        let text = "import { a } from \"./a.js\";\nimport \"./b.js\";\nexport { c };\n\
                    export * from \"./d.js\";\nexport type { E } from \"./e.js\"\n\
                    const f = import(\"./f.js\");\nimport.meta.url;\nexport function g() {}";
        let expected = [
            "const",
            "f",
            "=",
            "import",
            "(",
            "\"./f.js\"",
            ")",
            ";",
            "import",
            ".",
            "meta",
            ".",
            "url",
            ";",
            "export",
            "function",
            "g",
            "(",
            ")",
            "{",
            "}",
        ];
        assert_eq!(keys_of(text, Language::JavaScript), expected);
    }
}
