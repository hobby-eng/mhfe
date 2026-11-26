//! Any bytes as a request to `mhfe serve`, and any text as a line of its checksum file, through the
//! tool's own file `src/bin/mhfe/serve_http.rs`: a request head is cut at its limit, every answer
//! is one of the five the server gives, with every security header, and the page goes only to GET
//! or HEAD of "/" with the server's own Host; a checksum line splits into its 64 digits and a name
//! that put back together give the line.
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
    MAX_REQUEST_HEAD, SECURITY_HEADERS, SHA256_HEX_DIGITS, read_request_head, respond,
    split_checksum_line,
};

const HOST: &str = "127.0.0.1:8080";
const PAGE: &[u8] = b"<!doctype html>";

fuzz_target!(|data: &[u8]| {
    if let Ok(head) = read_request_head(&mut &data[..]) {
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
        for (name, value) in SECURITY_HEADERS {
            assert!(answer.contains(&format!("\r\n{name}: {value}\r\n")));
        }
        if status == "HTTP/1.1 200" {
            let request = head.lines().next().unwrap_or_default();
            assert!(request.starts_with("GET / HTTP/1.") || request.starts_with("HEAD / HTTP/1."));
        }
    }
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
