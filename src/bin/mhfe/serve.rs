//! `mhfe serve`: the launcher for the fast browser mode.
//!
//! A browser runs the four Argon2 lanes in parallel only on a cross-origin isolated page, and a
//! page opened as a file is never isolated. This command serves one HTML file from 127.0.0.1 with
//! the headers that make it isolated. It never receives or processes a secret: the page does all
//! the work in the browser.
//!
//! It serves a page only when the checksum file `mhfe-fast-mode.sha256` lies next to it and names
//! it with a matching SHA-256; otherwise it refuses with a message and serves nothing.
//!
//! The server is deliberately small: it answers GET and HEAD for "/" only, checks the Host
//! header against DNS rebinding, ignores request bodies and logs nothing. Each connection has
//! its own thread and a fixed time for its request, so a slow client cannot hold up the page.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anstream::eprintln;
use clap::Args;
use sha2::{Digest, Sha256};

use crate::exit::{Failure, SUCCESS};
use crate::style::{self, paint, ACCENT, MUTED};

/// The checksum file that must lie next to the page. Its name never changes, so a tool can ship
/// it beside its HTML file and the launcher finds it without being told. It holds one line in the
/// format `sha256sum` writes: the SHA-256 of the page, a space, a mode marker (a second space in
/// text mode, `*` in binary mode) and the page's file name.
pub const CHECKSUM_FILE: &str = "mhfe-fast-mode.sha256";

/// Hexadecimal digits of a SHA-256 digest.
const SHA256_HEX_DIGITS: usize = 64;

/// Longest request head accepted; real browsers send far less.
const MAX_REQUEST_HEAD: usize = 16 * 1024;
/// Time a client has for its whole request head. A limit on each read alone would let a client
/// that sends one byte at a time keep its connection open for ever.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
/// Time for sending the whole answer. A limit on each write alone would let a client that reads
/// slowly, or not at all, keep its connection and thread for ever.
const RESPONSE_DEADLINE: Duration = Duration::from_secs(10);
/// Connections answered at the same time; any further one is closed at once. A browser opens
/// only a few, and the cap keeps a flood of connections from starting a thread each.
const MAX_CONNECTIONS: usize = 16;

/// Sent with every response. COOP and COEP make the page cross-origin isolated; the others keep
/// it from being framed, sniffed, cached or followed by a referrer.
const SECURITY_HEADERS: [(&str, &str); 7] = [
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Embedder-Policy", "require-corp"),
    ("Content-Security-Policy", "frame-ancestors 'none'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
];

#[derive(Args)]
pub struct Options {
    /// The HTML file of the browser tool, with mhfe-fast-mode.sha256
    #[arg(long_help = file_help())]
    file: PathBuf,

    /// Print the address instead of opening the browser
    #[arg(long, long_help = no_browser_help())]
    no_browser: bool,
}

fn file_help() -> String {
    style::option_help(&[
        "The HTML file of the browser tool; mhfe-fast-mode.sha256 must lie next to it.",
        &format!(
            "{CHECKSUM_FILE} holds the SHA-256 of the page in the form sha256sum writes. The \
             page is served only when it matches, which catches a damaged, swapped or partly \
             updated page."
        ),
    ])
}

fn no_browser_help() -> String {
    style::option_help(&[
        "Print the address instead of opening the browser.",
        "Open the printed address yourself, in a browser on this computer. The server stops \
         when you press Ctrl+C.",
    ])
}

/// The top of `mhfe serve --help`.
pub fn about() -> String {
    style::command_about(&[
        "Serve a browser tool on this computer in fast mode",
        "A browser runs the faster, multi-threaded Argon2 only on a page served with special \
         headers. mhfe serve serves one page from this computer (127.0.0.1) with those \
         headers and opens it in the browser.",
    ])
}

/// The page named in the checksum file next to the program, if that file is there. `run` then
/// checks the page against it.
pub fn page_next_to_program() -> Result<Option<PathBuf>, Failure> {
    let program = std::env::current_exe()?;
    let Some(directory) = program.parent() else {
        return Ok(None);
    };
    if !directory.join(CHECKSUM_FILE).is_file() {
        return Ok(None);
    }
    let (_, name) = read_checksum_file(directory)?;
    Ok(Some(directory.join(name)))
}

/// The SHA-256 and the page name from the checksum file in `directory`.
fn read_checksum_file(directory: &Path) -> Result<(String, String), Failure> {
    let path = directory.join(CHECKSUM_FILE);
    let text = fs::read_to_string(&path).map_err(|error| {
        Failure::invalid_input(format!(
            "There is no readable {CHECKSUM_FILE} in {}: {error}. The fast mode serves a page \
             only when its checksum file lies next to it; nothing was served.",
            directory.display()
        ))
    })?;
    let malformed = || {
        Failure::invalid_input(format!(
            "{} must hold exactly one line, \"<SHA-256>  <page>.html\" or \"<SHA-256> \
             *<page>.html\"; nothing was served.",
            path.display()
        ))
    };
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return Err(malformed());
    };
    let (digest, name) = split_checksum_line(line).ok_or_else(malformed)?;
    let name = name.trim_end();
    // The name is a plain file name next to the checksum file, never a path.
    let is_plain_name = !name.contains(['/', '\\']) && name != ".." && name != ".";
    if !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !name.ends_with(".html")
        || !is_plain_name
    {
        return Err(malformed());
    }
    Ok((digest.to_ascii_lowercase(), name.to_owned()))
}

/// The digest and the file name of a line in the format sha256sum writes: 64 digits, a space,
/// then a second space in text mode (`--text`) or `*` in binary mode (`--binary`), then the name.
/// Only that one marker is removed; a name that itself starts with `*` stays as it is and so
/// does not match the page.
fn split_checksum_line(line: &str) -> Option<(&str, &str)> {
    let digest = line.get(..SHA256_HEX_DIGITS)?;
    let rest = line.get(SHA256_HEX_DIGITS..)?.strip_prefix(' ')?;
    let name = rest.strip_prefix(' ').or_else(|| rest.strip_prefix('*'))?;
    Some((digest, name))
}

/// The page, read once, after its checksum file next to it has named it with a matching SHA-256.
fn load_checked_page(file: &Path) -> Result<(Vec<u8>, String), Failure> {
    let directory = match file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let (expected, listed_name) = read_checksum_file(&directory)?;
    if listed_name != file_name(file) {
        return Err(Failure::invalid_input(format!(
            "{CHECKSUM_FILE} names {listed_name}, not {}; nothing was served.",
            file_name(file)
        )));
    }
    let page = fs::read(file).map_err(|error| {
        Failure::invalid_input(format!(
            "Cannot read {}: {error}; nothing was served.",
            file.display()
        ))
    })?;
    let digest = hex::encode(Sha256::digest(&page));
    if digest != expected {
        return Err(Failure::invalid_input(format!(
            "The SHA-256 of {} is {digest}, but {CHECKSUM_FILE} expects {expected}. The page has \
             changed or is not the one released; nothing was served.",
            file_name(file)
        )));
    }
    Ok((page, digest))
}

/// The end of `mhfe serve -h` and `--help`.
pub fn help() -> String {
    let examples = style::help_section(
        "Examples:",
        &[
            (
                "mhfe serve tool.html",
                "Serve the page and open it in the browser",
            ),
            (
                "mhfe serve --no-browser tool.html",
                "Serve the page and print its address to open by hand",
            ),
        ],
    );
    let note = style::help_note(&format!(
        "The page is served only when {CHECKSUM_FILE} lies next to it and holds its SHA-256, and \
         only to this computer (127.0.0.1). It sees none of your secrets: all the work happens in \
         the page."
    ));
    format!("{examples}\n{note}")
}

pub fn run(options: Options) -> Result<i32, Failure> {
    let (page, digest) = load_checked_page(&options.file)?;
    style::ok(format!(
        "SHA-256 of {} verified: {}",
        file_name(&options.file),
        paint(MUTED, &digest)
    ));

    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let address = format!("http://127.0.0.1:{port}/");
    let host = format!("127.0.0.1:{port}");
    if options.no_browser || open_browser(&address).is_err() {
        eprintln!("Open {} in your browser.", paint(ACCENT, &address));
    }
    style::ok(format!(
        "{} {}",
        paint(style::GOOD, "Fast mode is running."),
        paint(MUTED, "Close this window or press Ctrl+C to stop.")
    ));

    serve(listener, host, page, REQUEST_DEADLINE);
    Ok(SUCCESS)
}

/// Answers every connection in its own thread, at most MAX_CONNECTIONS at a time. A failed
/// connection or a broken request is dropped; the server goes on serving the page.
fn serve(listener: TcpListener, host: String, page: Vec<u8>, deadline: Duration) {
    let host: Arc<str> = host.into();
    let page: Arc<[u8]> = page.into();
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming().flatten() {
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            continue; // Dropping the stream closes the connection.
        }
        let (host, page, finished) = (Arc::clone(&host), Arc::clone(&page), Arc::clone(&active));
        let spawned = thread::Builder::new().spawn(move || {
            let _ = answer(stream, &host, &page, deadline);
            finished.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            // The thread never ran, so its connection was closed and nothing is counted down.
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

pub fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Opens the default browser; the address holds no secret.
fn open_browser(address: &str) -> io::Result<()> {
    let mut command = if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(windows) {
        let mut command = Command::new("cmd");
        command.args(["/C", "start", ""]);
        command
    } else {
        Command::new("xdg-open")
    };
    command.arg(address).spawn().map(|_| ())
}

/// Reads one request and writes one response, then closes the connection.
fn answer(stream: TcpStream, host: &str, page: &[u8], deadline: Duration) -> io::Result<()> {
    let mut reader = BufReader::new(UntilDeadline {
        stream: stream.try_clone()?,
        deadline: Instant::now() + deadline,
    });
    let response = match read_request_head(&mut reader) {
        Ok(head) => respond(&head, host, page),
        Err(_) => Response::status(400, "Bad Request"),
    };
    write_until(
        &stream,
        &response.into_bytes(),
        Instant::now() + RESPONSE_DEADLINE,
    )
}

/// Writes all of `bytes`, but gives up at `deadline`; the connection is then closed.
fn write_until(mut stream: &TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        // A zero timeout would mean "wait for ever" to the operating system; it is refused.
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// A connection that can be read until a fixed moment and then reports a timeout.
struct UntilDeadline {
    stream: TcpStream,
    deadline: Instant,
}

impl Read for UntilDeadline {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        // A zero timeout would mean "wait for ever" to the operating system; it is refused.
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buffer)
    }
}

fn read_request_head(reader: &mut impl BufRead) -> io::Result<String> {
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

struct Response {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    /// For HEAD: the length of the body a GET would receive, sent without the body.
    head_only: bool,
}

impl Response {
    fn status(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            content_type: "text/plain; charset=utf-8",
            body: format!("{status} {reason}\n").into_bytes(),
            head_only: false,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
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
        if !self.head_only {
            bytes.extend_from_slice(&self.body);
        }
        bytes
    }
}

/// The whole routing: GET or HEAD of "/" with the exact Host header gets the page, anything
/// else an error. The Host check stops DNS rebinding: a web page on another site whose name
/// was made to resolve to 127.0.0.1 would send its own name as Host.
fn respond(head: &str, host: &str, page: &[u8]) -> Response {
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Response::status(400, "Bad Request");
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
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
            body: page.to_vec(),
            head_only: method == "HEAD",
        },
        _ => Response::status(405, "Method Not Allowed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "127.0.0.1:43210";
    const PAGE: &[u8] = b"<!doctype html><title>tool</title>";

    fn request(method: &str, target: &str, host: &str) -> String {
        format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n\r\n")
    }

    fn text(response: Response) -> String {
        String::from_utf8(response.into_bytes()).unwrap()
    }

    #[test]
    fn serves_the_page_with_every_security_header() {
        let response = text(respond(&request("GET", "/", HOST), HOST, PAGE));
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Type: text/html; charset=utf-8\r\n"));
        for (name, value) in SECURITY_HEADERS {
            assert!(response.contains(&format!("{name}: {value}\r\n")), "{name}");
        }
        assert!(response.ends_with("<!doctype html><title>tool</title>"));
    }

    #[test]
    fn head_sends_the_headers_without_the_body() {
        let response = text(respond(&request("HEAD", "/", HOST), HOST, PAGE));
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains(&format!("Content-Length: {}\r\n", PAGE.len())));
        assert!(response.ends_with("\r\n\r\n"));
    }

    #[test]
    fn refuses_other_hosts_against_dns_rebinding() {
        for host in [
            "localhost:43210",
            "127.0.0.1",
            "127.0.0.1:1",
            "evil.example:43210",
            "",
        ] {
            let response = text(respond(&request("GET", "/", host), HOST, PAGE));
            assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{host:?}");
        }
        let without_host = "GET / HTTP/1.1\r\n\r\n";
        assert!(text(respond(without_host, HOST, PAGE)).starts_with("HTTP/1.1 403"));
        let two_hosts = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nHost: {HOST}\r\n\r\n");
        assert!(text(respond(&two_hosts, HOST, PAGE)).starts_with("HTTP/1.1 403"));
    }

    #[test]
    fn refuses_other_paths_and_methods() {
        for target in ["/index.html", "/../", "//", "/?x=1", "*"] {
            let response = text(respond(&request("GET", target, HOST), HOST, PAGE));
            assert!(response.starts_with("HTTP/1.1 404"), "{target}");
        }
        for method in ["POST", "PUT", "DELETE", "OPTIONS", "get"] {
            let response = text(respond(&request(method, "/", HOST), HOST, PAGE));
            assert!(response.starts_with("HTTP/1.1 405"), "{method}");
        }
        for malformed in [
            "GET /\r\n\r\n",
            "GET / HTTP/2\r\nHost: x\r\n\r\n",
            "GET  / HTTP/1.1\r\n\r\n",
        ] {
            assert!(
                text(respond(malformed, HOST, PAGE)).starts_with("HTTP/1.1 400"),
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn stops_reading_an_endless_request_head() {
        let endless = "GET / HTTP/1.1\r\n".to_owned() + &"X-Filler: a\r\n".repeat(5000);
        let mut reader = BufReader::new(endless.as_bytes());
        assert!(read_request_head(&mut reader).is_err());
    }

    /// Starts the server loop on a free port with a short request deadline; returns the port.
    fn start_server(deadline: Duration) -> u16 {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let host = format!("127.0.0.1:{port}");
        thread::spawn(move || serve(listener, host, PAGE.to_vec(), deadline));
        port
    }

    fn get(port: u16) -> String {
        let mut connection = TcpStream::connect(("127.0.0.1", port)).unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let host = format!("127.0.0.1:{port}");
        connection
            .write_all(request("GET", "/", &host).as_bytes())
            .unwrap();
        let mut response = String::new();
        connection.read_to_string(&mut response).unwrap();
        response
    }

    /// A client that never reads a large answer loses its connection at the deadline, although
    /// every single write makes some progress until the buffers are full.
    #[test]
    fn a_client_that_does_not_read_is_dropped_at_the_response_deadline() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let _idle = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_side, _) = listener.accept().unwrap();
        let answer = vec![b'x'; 64 * 1024 * 1024];
        let started = Instant::now();
        let result = write_until(&server_side, &answer, started + Duration::from_millis(500));
        // Windows takes a whole answer of this size into its loopback buffers, so there the write
        // can finish in time; what every system must show is that it never outlasts the deadline.
        if cfg!(not(windows)) {
            assert!(
                result.is_err(),
                "the answer cannot fit into the socket buffers"
            );
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "stopped near the deadline"
        );
    }

    #[test]
    fn a_slow_client_neither_holds_up_others_nor_outlives_the_deadline() {
        let port = start_server(Duration::from_millis(500));
        // This client sends one byte of its request head every 100 ms and never finishes it.
        let mut slow = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut dripping = slow.try_clone().unwrap();
        thread::spawn(move || {
            for byte in b"GET / HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaa".iter() {
                if dripping.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        let started = Instant::now();
        assert!(get(port).starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "the page came at once"
        );
        slow.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut answer = Vec::new();
        let _ = slow.read_to_end(&mut answer);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "dropped at its deadline"
        );
    }

    /// A fresh folder with the page in it, removed when the test ends.
    struct TestFolder(PathBuf);

    impl TestFolder {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("mhfe-serve-{name}-{}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("tool.html"), PAGE).unwrap();
            Self(path)
        }

        fn page(&self) -> PathBuf {
            self.0.join("tool.html")
        }

        fn write_checksum_file(&self, text: &str) {
            fs::write(self.0.join(CHECKSUM_FILE), text).unwrap();
        }
    }

    impl Drop for TestFolder {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn refusal(folder: &TestFolder) -> String {
        load_checked_page(&folder.page()).unwrap_err().message
    }

    #[test]
    fn serves_only_a_page_named_with_its_sha256_in_the_checksum_file() {
        let digest = hex::encode(Sha256::digest(PAGE));
        let folder = TestFolder::new("valid");
        folder.write_checksum_file(&format!("{digest}  tool.html\n"));
        let (page, checked) = load_checked_page(&folder.page()).unwrap();
        assert_eq!((page.as_slice(), checked.as_str()), (PAGE, digest.as_str()));
        // Upper-case digits are accepted too.
        folder.write_checksum_file(&format!("{}  tool.html\n", digest.to_uppercase()));
        assert!(load_checked_page(&folder.page()).is_ok());
    }

    /// AUD-004-FUN002: the literal output of `sha256sum --text tool.html` and
    /// `sha256sum --binary tool.html` (GNU coreutils) for PAGE. Both are accepted.
    #[test]
    fn accepts_the_text_and_binary_output_of_sha256sum() {
        const DIGEST: &str = "a760013b4e475f909edfdcb6e7f228ecd5536cca669741ce43972ecffd5b6f6c";
        assert_eq!(hex::encode(Sha256::digest(PAGE)), DIGEST);
        let folder = TestFolder::new("modes");
        for line in [
            "a760013b4e475f909edfdcb6e7f228ecd5536cca669741ce43972ecffd5b6f6c  tool.html\n",
            "a760013b4e475f909edfdcb6e7f228ecd5536cca669741ce43972ecffd5b6f6c *tool.html\n",
        ] {
            folder.write_checksum_file(line);
            let (_, checked) = load_checked_page(&folder.page()).unwrap();
            assert_eq!(checked, DIGEST, "{line:?}");
        }
        // Only one marker is removed: a further "*" belongs to the name, which then differs.
        for line in [
            format!("{DIGEST}  *tool.html\n"),
            format!("{DIGEST} **tool.html\n"),
        ] {
            folder.write_checksum_file(&line);
            assert!(
                refusal(&folder).contains("names *tool.html, not tool.html"),
                "{line:?}"
            );
        }
    }

    #[test]
    fn refuses_without_a_matching_checksum_file() {
        let digest = hex::encode(Sha256::digest(PAGE));
        let folder = TestFolder::new("refused");
        assert!(refusal(&folder).contains("There is no readable mhfe-fast-mode.sha256"));

        folder.write_checksum_file(&format!("{}  tool.html\n", "00".repeat(32)));
        assert!(refusal(&folder).contains("but mhfe-fast-mode.sha256 expects"));

        folder.write_checksum_file(&format!("{digest}  other.html\n"));
        assert!(refusal(&folder).contains("names other.html, not tool.html"));

        for malformed in [
            String::new(),
            format!("{digest} tool.html\n"),
            format!("{digest}*tool.html\n"),
            format!("{digest}\ttool.html\n"),
            format!("{digest}  tool.html\n{digest}  tool.html\n"),
            format!("{digest}  tool.html\n{digest} *tool.html\n"),
            format!("{digest}  tool.txt\n"),
            format!("{digest}  ../tool.html\n"),
            format!("{digest} *../tool.html\n"),
            format!("{}  tool.html\n", &digest[..63]),
            format!("{}g *tool.html\n", &digest[..63]),
        ] {
            folder.write_checksum_file(&malformed);
            assert!(
                refusal(&folder).contains("must hold exactly one line"),
                "{malformed:?}"
            );
        }
        // Every refusal says that nothing was served.
        assert!(refusal(&folder).contains("nothing was served"));
    }
}
