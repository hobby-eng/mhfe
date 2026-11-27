//! What `mhfe serve` reads from a client and from its checksum file, and the answer it writes:
//! plain functions of their input, with no state, so that the fuzz target `http` of `fuzz/` takes
//! this very file in (RUST-18). Only the standard library is used here.

use std::borrow::Cow;
use std::io::{self, BufRead, Read};

/// Hexadecimal digits of a SHA-256 digest.
pub(crate) const SHA256_HEX_DIGITS: usize = 64;
/// Longest request head accepted; real browsers send far less.
pub(crate) const MAX_REQUEST_HEAD: usize = 16 * 1024;

/// Sent with every response. COOP and COEP make the page cross-origin isolated; the others keep
/// it from being framed, sniffed, cached or followed by a referrer.
pub(crate) const SECURITY_HEADERS: [(&str, &str); 7] = [
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Embedder-Policy", "require-corp"),
    ("Content-Security-Policy", "frame-ancestors 'none'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
];

/// The digest and the file name of a line in the format sha256sum writes: 64 digits, a space,
/// then a second space in text mode (`--text`) or `*` in binary mode (`--binary`), then the name.
/// Only that one marker is removed; a name that itself starts with `*` stays as it is and so
/// does not match the page.
pub(crate) fn split_checksum_line(line: &str) -> Option<(&str, &str)> {
    let digest = line.get(..SHA256_HEX_DIGITS)?;
    let rest = line.get(SHA256_HEX_DIGITS..)?.strip_prefix(' ')?;
    let name = rest.strip_prefix(' ').or_else(|| rest.strip_prefix('*'))?;
    Some((digest, name))
}

pub(crate) fn read_request_head(reader: &mut impl BufRead) -> io::Result<String> {
    let mut head = String::new();
    let mut limited = reader.take(MAX_REQUEST_HEAD as u64);
    loop {
        let before = head.len();
        if limited.read_line(&mut head)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let line = &head[before..];
        if line == "\r\n" || line == "\n" {
            return Ok(head);
        }
    }
}

/// An answer: its head, then its body, which for the page is the server's one copy of it, written
/// as it is and never copied per connection (AUD-051-SEC006).
pub(crate) struct Response<'a> {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: Cow<'a, [u8]>,
    /// For HEAD: the length of the body a GET would receive, sent without the body.
    head_only: bool,
}

impl<'a> Response<'a> {
    pub(crate) fn status(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            content_type: "text/plain; charset=utf-8",
            body: Cow::Owned(format!("{status} {reason}\n").into_bytes()),
            head_only: false,
        }
    }

    /// The status line and the headers, with the empty line that ends them.
    pub(crate) fn head(&self) -> Vec<u8> {
        let mut bytes = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len()
        )
        .into_bytes();
        for (name, value) in SECURITY_HEADERS {
            bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        bytes.extend_from_slice(b"\r\n");
        bytes
    }

    /// What follows the head: the body, or nothing for HEAD.
    pub(crate) fn body(&self) -> &[u8] {
        if self.head_only {
            return &[];
        }
        &self.body
    }
}

/// The whole routing: GET or HEAD of "/" with the exact Host header gets the page, anything
/// else an error. The Host check stops DNS rebinding: a web page on another site whose name
/// was made to resolve to 127.0.0.1 would send its own name as Host. A HEAD request gets the
/// head of each answer without its body, an error too (RFC 9110, 9.3.2; AUD-051-FUN002).
pub(crate) fn respond<'a>(head: &str, host: &str, page: &'a [u8]) -> Response<'a> {
    let mut response = route(head, host, page);
    let request_line = head.lines().next().unwrap_or_default();
    response.head_only = request_line.split(' ').next() == Some("HEAD");
    response
}

fn route<'a>(head: &str, host: &str, page: &'a [u8]) -> Response<'a> {
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Response::status(400, "Bad Request");
    };
    // An empty method or target, from two spaces in a row, is malformed, as the Python launcher
    // reads it (AUD-051-API002).
    if method.is_empty() || target.is_empty() || (version != "HTTP/1.1" && version != "HTTP/1.0") {
        return Response::status(400, "Bad Request");
    }

    let mut host_headers = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim());
    let host_matches = host_headers.next() == Some(host) && host_headers.next().is_none();
    if !host_matches {
        return Response::status(403, "Forbidden");
    }

    if target != "/" {
        return Response::status(404, "Not Found");
    }
    match method {
        "GET" | "HEAD" => Response {
            status: 200,
            reason: "OK",
            content_type: "text/html; charset=utf-8",
            body: Cow::Borrowed(page),
            head_only: false,
        },
        _ => Response::status(405, "Method Not Allowed"),
    }
}
