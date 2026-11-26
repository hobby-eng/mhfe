//! Any bytes, and a head built of whole lines from them, as a request to `mhfe serve`, and any text
//! as a line of its checksum file, through the tool's own file `src/bin/mhfe/serve_http.rs`: a
//! request head is cut at its limit, every answer is one of the five the server gives, with the
//! security headers written out below, and exactly a GET or HEAD of "/" with one Host, the
//! server's own, gets the page, a HEAD without its bytes; a checksum line splits into its 64
//! digits and a name that put back together give the line. The rules are stated here again, apart
//! from the server's code, so that a change of it is found.
#![no_main]
#![allow(
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its assertions are its checks"
)]

#[allow(
    dead_code,
    reason = "the server's file, of which the target calls only some items"
)]
#[path = "../../src/bin/mhfe/serve_http.rs"]
mod serve_http;

use libfuzzer_sys::fuzz_target;
use serve_http::{
    MAX_REQUEST_HEAD, SHA256_HEX_DIGITS, read_request_head, respond, split_checksum_line,
};

const HOST: &str = "127.0.0.1:8080";
const PAGE: &[u8] = b"<!doctype html>";
/// The headers of every answer.
const HEADERS: [&str; 7] = [
    "Cross-Origin-Opener-Policy: same-origin",
    "Cross-Origin-Embedder-Policy: require-corp",
    "Content-Security-Policy: frame-ancestors 'none'",
    "X-Frame-Options: DENY",
    "X-Content-Type-Options: nosniff",
    "Referrer-Policy: no-referrer",
    "Cache-Control: no-store",
];

/// The method of a request that gets the page: GET or HEAD of "/" in HTTP/1.1 or 1.0, with one
/// Host header, whose value is the server's own.
fn page_method(head: &str) -> Option<&str> {
    let mut lines = head.lines();
    let request: Vec<&str> = lines.next().unwrap_or_default().split(' ').collect();
    let hosts: Vec<&str> = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim())
        .collect();
    match request.as_slice() {
        [method @ ("GET" | "HEAD"), "/", "HTTP/1.1" | "HTTP/1.0"] if hosts == [HOST] => {
            Some(*method)
        }
        _ => None,
    }
}

/// Lines a request head is built of, one for each fuzz byte, so that the requests that get the
/// page, and those a little off them, come up at once: raw bytes seldom hold the exact Host.
const LINES: [&str; 8] = [
    "GET / HTTP/1.1",
    "HEAD / HTTP/1.0",
    "POST / HTTP/1.1",
    "GET /x HTTP/1.1",
    "Host: 127.0.0.1:8080",
    "host:127.0.0.1:8080 ",
    "Host: 127.0.0.1:8081",
    "Accept: */*",
];

/// Checks the answer to a request head that the server read.
fn check(data: &[u8]) {
    let Ok(head) = read_request_head(&mut &data[..]) else {
        return;
    };
    assert!(head.len() <= MAX_REQUEST_HEAD);
    // The head ends at its first empty line, which may be its only one.
    let before = head.strip_suffix('\n').unwrap_or_default();
    let before = before.strip_suffix('\r').unwrap_or(before);
    assert!(head.ends_with('\n') && (before.is_empty() || before.ends_with('\n')));
    let answer = String::from_utf8_lossy(&respond(&head, HOST, PAGE).into_bytes()).into_owned();
    let status = &answer[..answer.len().min(12)];
    assert!(
        [
            "HTTP/1.1 200",
            "HTTP/1.1 400",
            "HTTP/1.1 403",
            "HTTP/1.1 404",
            "HTTP/1.1 405"
        ]
        .contains(&status)
    );
    for header in HEADERS {
        assert!(answer.contains(&format!("\r\n{header}\r\n")));
    }
    let (_, body) = answer.split_once("\r\n\r\n").unwrap_or_default();
    let method = page_method(&head);
    assert_eq!(status == "HTTP/1.1 200", method.is_some());
    match method {
        Some(method) => {
            let length = format!("\r\nContent-Length: {}\r\n", PAGE.len());
            assert!(answer.contains(&length));
            let sent: &[u8] = if method == "HEAD" { b"" } else { PAGE };
            assert_eq!(body.as_bytes(), sent);
        }
        None => assert_ne!(body.as_bytes(), PAGE),
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);
    let built: String = (data.iter().take(8))
        .map(|&byte| format!("{}\r\n", LINES[usize::from(byte % 8)]))
        .chain(["\r\n".to_owned()])
        .collect();
    check(built.as_bytes());
    if let Ok(line) = std::str::from_utf8(data)
        && let Some((digest, name)) = split_checksum_line(line)
    {
        assert_eq!(digest.len(), SHA256_HEX_DIGITS);
        assert!(
            [" ", "*"]
                .iter()
                .any(|marker| line == format!("{digest} {marker}{name}"))
        );
    }
});
