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

use clap::Args;
use sha2::{Digest, Sha256};

use crate::exit::{Failure, SUCCESS};
use crate::style::{self, paint, ACCENT, MUTED};

/// The checksum file that must lie next to the page. Its name never changes, so a tool can ship
/// it beside its HTML file and the launcher finds it without being told. It holds one line in the
/// format `sha256sum` writes: the SHA-256 of the page, a space, a mode marker (a second space in
/// text mode, `*` in binary mode) and the page's file name.
// Deliberate copy in the standalone Python launcher; its parity tests compare both.
pub(crate) const CHECKSUM_FILE: &str = "mhfe-fast-mode.sha256";
/// What a checksum file must hold, in words rather than a pattern with two spaces, which the
/// wrapping of a message would join into one (AUD-023-UI009). Deliberate copy: the Python launcher
/// (packaging/mhfe-fast-mode.py), which ships alone beside the browser package, says the same, and
/// scripts/verify-fast-mode-script.py keeps both equal.
const MALFORMED: &str = "must hold exactly one line: the page's SHA-256, two spaces and its file \
                         name, or one space and * before the name; nothing was served.";

// Deliberate copy in the standalone Python launcher, checked by its parity tests.
const HTML_SUFFIX: &str = ".html";
const NON_HTML: &str = "The fast mode serves only a page whose name ends in lower-case {suffix}; \
                        nothing was served.";

/// Hexadecimal digits of a SHA-256 digest.
// Deliberate copy in the standalone Python launcher; its parity tests compare both.
const SHA256_HEX_DIGITS: usize = 64;

/// The most a checksum file may hold: its one line is about 80 bytes. A longer file is malformed,
/// and nothing beyond this is read of it (AUD-024-FUN005).
// Deliberate copy in the standalone Python launcher; its parity tests compare both.
const MAX_CHECKSUM_FILE: u64 = 4 * 1024;

/// The most a page may hold: a tool's page is a few megabytes. A larger file is refused, and
/// nothing beyond this is read of it (AUD-024-FUN005).
// Deliberate copy in the standalone Python launcher; its parity tests compare both.
const MAX_PAGE: u64 = 64 * 1024 * 1024;

/// Longest request head accepted; real browsers send far less.
// Deliberate copy in the standalone Python launcher; its parity tests compare both.
const MAX_REQUEST_HEAD: usize = 16 * 1024;
/// Time a client has for its whole request head. A limit on each read alone would let a client
/// that sends one byte at a time keep its connection open for ever.
// Deliberate copy in the standalone Python launcher; its parity tests compare both.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
/// Time for sending the whole answer. A limit on each write alone would let a client that reads
/// slowly, or not at all, keep its connection and thread for ever.
// Deliberate copy in the standalone Python launcher; its parity tests compare both.
const RESPONSE_DEADLINE: Duration = Duration::from_secs(10);
/// Connections answered at the same time; any further one is closed at once. A browser opens
/// only a few, and the cap keeps a flood of connections from starting a thread each.
// Deliberate copy in the standalone Python launcher; its parity tests compare both.
const MAX_CONNECTIONS: usize = 16;
/// Time the listener waits after a connection it could not accept, such as when the process has
/// no file descriptor left, so that it does not spin; it then goes on serving (AUD-023-FUN003).
// Deliberate copy in the standalone Python launcher; its parity tests compare both.
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

/// Sent with every response. COOP and COEP make the page cross-origin isolated; the others keep
/// it from being framed, sniffed, cached or followed by a referrer.
// Deliberate copy in the standalone Python launcher; its parity tests compare both.
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
pub(crate) struct Options {
    /// The HTML file of the browser tool, with mhfe-fast-mode.sha256
    #[arg(long_help = file_help())]
    file: PathBuf,

    /// Print the address instead of opening the browser
    #[arg(long, long_help = no_browser_help())]
    no_browser: bool,
}

fn file_help() -> String {
    style::option_help(&[
        &format!("The browser tool's file, ending in lower-case {HTML_SUFFIX}; {CHECKSUM_FILE} must lie next to it."),
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

/// The one-line summary of the command: `-h`, the first line of `--help`, and its menu entry.
pub(crate) const SUMMARY: &str = "Serve a browser tool on this computer in fast mode";

/// The top of `mhfe serve --help`.
pub(crate) fn about() -> String {
    style::command_about(&[
        SUMMARY,
        "A browser runs the faster, multi-threaded Argon2 only on a page served with special \
         headers. mhfe serve serves one page from this computer (127.0.0.1) with those \
         headers and opens it in the browser.",
    ])
}

/// The page named in the checksum file next to the program, if that file is there, once the page
/// is there and has its SHA-256: the menu offers the fast mode only then, and says why not
/// otherwise (AUD-023-DOC008). `run` checks the page again, as it may change in between.
pub(crate) fn page_next_to_program() -> Result<Option<PathBuf>, Failure> {
    let program = std::env::current_exe()?;
    match program.parent() {
        Some(directory) => checked_page_in(directory),
        None => Ok(None),
    }
}

/// [`page_next_to_program`] for the program's `directory`.
fn checked_page_in(directory: &Path) -> Result<Option<PathBuf>, Failure> {
    if !directory.join(CHECKSUM_FILE).is_file() {
        return Ok(None);
    }
    let (_, name) = read_checksum_file(directory)?;
    let page = directory.join(name);
    load_checked_page(&page)?;
    Ok(Some(page))
}

/// The SHA-256 and the page name from the checksum file in `directory`.
// Deliberate copy: packaging/mhfe-fast-mode.py ships alone; parity tests cover both.
fn read_checksum_file(directory: &Path) -> Result<(String, String), Failure> {
    let path = directory.join(CHECKSUM_FILE);
    let unreadable = |error: &dyn std::fmt::Display| {
        Failure::invalid_input(format!(
            "There is no readable {CHECKSUM_FILE} in {}: {error}. The fast mode serves a page \
             only when its checksum file lies next to it; nothing was served.",
            style::shown_path(directory)
        ))
    };
    let malformed = || Failure::invalid_input(format!("{} {MALFORMED}", style::shown_path(&path)));
    let bytes = read_regular_file(&path, MAX_CHECKSUM_FILE)
        .map_err(|error| unreadable(&error))?
        .ok_or_else(malformed)?;
    let text = String::from_utf8(bytes).map_err(|error| unreadable(&error))?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return Err(malformed());
    };
    let (digest, name) = split_checksum_line(line).ok_or_else(malformed)?;
    let name = name.trim_end();
    // The name is a plain file name next to the checksum file, never a path, and holds no control
    // character, which a terminal would carry out where the name is shown (AUD-015-SEC002).
    let is_plain_name = !name.contains(['/', '\\'])
        && name != ".."
        && name != "."
        && !name.chars().any(char::is_control);
    if !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) || !is_plain_name {
        return Err(malformed());
    }
    if !name.ends_with(HTML_SUFFIX) {
        return Err(Failure::invalid_input(
            NON_HTML.replace("{suffix}", HTML_SUFFIX),
        ));
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
// Deliberate copy: packaging/mhfe-fast-mode.py ships alone; parity tests cover both.
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
    let page = read_regular_file(file, MAX_PAGE)
        .map_err(|error| {
            Failure::invalid_input(format!(
                "Cannot read {}: {error}; nothing was served.",
                style::shown_path(file)
            ))
        })?
        .ok_or_else(|| {
            Failure::invalid_input(format!(
                "{} is larger than {} MiB, more than any page of the tools; nothing was served.",
                style::shown_path(file),
                MAX_PAGE >> 20
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

/// At most `limit` bytes of `path`, which must be a regular file: a FIFO, a device or a folder is
/// refused before anything is read, opened without waiting so that a FIFO with no writer does not
/// block. `None` for a longer file, of which nothing beyond the limit is read (AUD-024-FUN005).
fn read_regular_file(path: &Path, limit: u64) -> io::Result<Option<Vec<u8>>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "it is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= limit).then_some(bytes))
}

/// The end of `mhfe serve -h` and `--help`.
pub(crate) fn help() -> String {
    style::examples_with_note(
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
        &format!(
            "The page is served only when {CHECKSUM_FILE} lies next to it and holds its SHA-256, \
             and only to this computer (127.0.0.1). It sees none of your secrets: all the work \
             happens in the page."
        ),
    )
}

/// The title of `mhfe serve`.
// Deliberate copy in the standalone Python launcher; its parity tests compare both.
const TITLE: &str = "Fast mode";

// Deliberate copy: packaging/mhfe-fast-mode.py ships alone; parity tests cover both.
pub(crate) fn run(options: Options) -> Result<i32, Failure> {
    style::title(TITLE);
    let (page, digest) = load_checked_page(&options.file)?;
    // The digest on a line of its own, so that wrapping never splits it (AUD-023-UI007).
    style::ok(format!("SHA-256 of {} verified", file_name(&options.file)));
    style::fact("SHA-256", paint(MUTED, &digest));

    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let address = format!("http://127.0.0.1:{port}/");
    let host = format!("127.0.0.1:{port}");
    // The address is always shown: an opener that starts can still fail, or open an unwanted
    // browser (AUD-023-UI010).
    let shown = paint(ACCENT, &address);
    if options.no_browser || open_browser(&address).is_err() {
        eprintln!("Open {shown} in your browser.");
    } else {
        eprintln!("Opened {shown}; if no browser shows it, open it yourself.");
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
    for stream in listener.incoming() {
        // A connection that cannot be accepted is dropped, after a pause, and serving goes on.
        let Ok(stream) = stream else {
            thread::sleep(ACCEPT_ERROR_PAUSE);
            continue;
        };
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

/// The file name of `path` as a message or the menu shows it, control characters escaped.
pub(crate) fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| style::escaped(&name.to_string_lossy()))
        .unwrap_or_else(|| style::shown_path(path))
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
        // A head that does end, but after more than MAX_REQUEST_HEAD bytes: refused only by the
        // limit, so that the test fails without it (AUD-023-ARC017). One that ends within it is
        // read.
        let filler = "X-Filler: a\r\n".repeat(MAX_REQUEST_HEAD / 13 + 1);
        let long = format!("GET / HTTP/1.1\r\n{filler}\r\n");
        assert!(long.len() > MAX_REQUEST_HEAD);
        assert!(read_request_head(&mut BufReader::new(long.as_bytes())).is_err());
        let within = format!("GET / HTTP/1.1\r\n{}\r\n", "X-Filler: a\r\n".repeat(100));
        assert!(read_request_head(&mut BufReader::new(within.as_bytes())).is_ok());
    }

    /// While MAX_CONNECTIONS clients hold their slots, one more is closed at once, and once they
    /// are gone the page is served again (AUD-023-ARC017).
    #[test]
    fn connections_beyond_the_limit_are_closed_at_once() {
        let port = start_server(Duration::from_secs(2));
        let idle: Vec<TcpStream> = (0..MAX_CONNECTIONS)
            .map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap())
            .collect();
        thread::sleep(Duration::from_millis(200));
        let mut extra = TcpStream::connect(("127.0.0.1", port)).unwrap();
        extra
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let started = Instant::now();
        let mut answer = Vec::new();
        let _ = extra.read_to_end(&mut answer);
        assert!(answer.is_empty(), "the extra connection was answered");
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "closed at once, not at a deadline"
        );
        drop(idle);
        thread::sleep(Duration::from_millis(200));
        assert!(get(port).starts_with("HTTP/1.1 200 OK\r\n"));
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
        let (send, receive) = std::sync::mpsc::channel();
        let writer = thread::spawn(move || {
            let result = write_until(&server_side, &answer, started + Duration::from_millis(500));
            let _ = send.send(result);
        });
        let result = receive
            .recv_timeout(Duration::from_secs(3))
            .expect("response write did not finish within the test limit");
        writer.join().expect("the response writer did not panic");
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

    /// A folder or file name in a message carries no control sequence a terminal would carry out
    /// (AUD-015-SEC002, through the parent folder's name: AUD-016).
    #[test]
    fn a_shown_path_holds_no_control_character() {
        let path = std::path::Path::new("/tmp/x\u{1b}]0;TITLE\u{7}y/tool.html");
        for shown in [style::shown_path(path), file_name(path)] {
            assert!(!shown.chars().any(char::is_control), "{shown}");
        }
        assert_eq!(
            style::shown_path(path),
            "/tmp/x\\u{1b}]0;TITLE\\u{7}y/tool.html"
        );
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

        for malformed in shared_cases("checksumFiles", "malformed") {
            let malformed = filled(&malformed, &digest);
            folder.write_checksum_file(&malformed);
            assert!(
                refusal(&folder).contains("must hold exactly one line"),
                "{malformed:?}"
            );
        }
        // Every refusal says that nothing was served.
        assert!(refusal(&folder).contains("nothing was served"));
    }

    #[test]
    fn a_non_html_name_is_refused_apart_from_the_checksum_line_format() {
        let folder = TestFolder::new("non-html-name");
        let digest = hex::encode(Sha256::digest(PAGE));
        for case in shared_cases("checksumFiles", "nonHtml") {
            folder.write_checksum_file(&filled(&case, &digest));
            let failure = read_checksum_file(&folder.0).unwrap_err();
            assert_eq!(failure.exit_code, crate::exit::INVALID_INPUT);
            assert_eq!(failure.message, NON_HTML.replace("{suffix}", HTML_SUFFIX));
        }
    }

    /// The cases of `kind` in `group` of the cases both launchers decide alike
    /// (tests/fixtures/fast-mode-cases.json, which scripts/verify-fast-mode-script.py reads too).
    fn shared_cases(group: &str, kind: &str) -> Vec<String> {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/fast-mode-cases.json"))
                .unwrap();
        cases[group][kind]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| case.as_str().unwrap().to_owned())
            .collect()
    }

    /// A shared case with the page's `digest` and the address served in it.
    fn filled(case: &str, digest: &str) -> String {
        case.replace("{digest63}", digest.get(..63).unwrap_or_default())
            .replace("{digest}", digest)
            .replace("{host}", HOST)
    }

    #[test]
    fn serves_every_shared_checksum_file_that_is_well_formed() {
        let digest = hex::encode(Sha256::digest(PAGE));
        let folder = TestFolder::new("shared");
        for served in shared_cases("checksumFiles", "served") {
            folder.write_checksum_file(&filled(&served, &digest));
            assert!(load_checked_page(&folder.page()).is_ok(), "{served:?}");
        }
    }

    /// Every shared request head gets the status the Python launcher gives it (AUD-024-FUN007).
    #[test]
    fn every_shared_request_head_gets_its_status() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/fast-mode-cases.json"))
                .unwrap();
        for case in cases["requestHeads"].as_array().unwrap() {
            let head = filled(case["head"].as_str().unwrap(), "");
            let bytes: Vec<u8> = if case["encoding"] == "latin-1" {
                head.chars()
                    .map(|character| u8::try_from(u32::from(character)).unwrap())
                    .collect()
            } else {
                head.clone().into_bytes()
            };
            let status = match read_request_head(&mut io::Cursor::new(bytes)) {
                Ok(read) => respond(&read, HOST, PAGE).status,
                Err(_) => 400,
            };
            assert_eq!(u64::from(status), case["status"], "{head:?}");
        }
    }

    /// A checksum file or a page that is not a regular file, or too large, is refused before it is
    /// read whole (AUD-024-FUN005).
    #[test]
    fn refuses_a_file_too_large_or_not_regular() {
        let digest = hex::encode(Sha256::digest(PAGE));
        let folder = TestFolder::new("bounded");
        folder.write_checksum_file(&format!("{digest}  tool.html\n{}", " ".repeat(4096)));
        assert!(refusal(&folder).contains("must hold exactly one line"));
        fs::remove_file(folder.0.join(CHECKSUM_FILE)).unwrap();
        fs::create_dir(folder.0.join(CHECKSUM_FILE)).unwrap();
        assert!(refusal(&folder).contains("it is not a regular file"));
        fs::remove_dir(folder.0.join(CHECKSUM_FILE)).unwrap();
        // A page one byte over the limit: a sparse file, which takes no room on the disk.
        let file = fs::File::create(folder.page()).unwrap();
        file.set_len(MAX_PAGE + 1).unwrap();
        folder.write_checksum_file(&format!("{digest}  tool.html\n"));
        assert!(
            refusal(&folder).contains("is larger than 64 MiB"),
            "{}",
            refusal(&folder)
        );
        #[cfg(unix)]
        {
            // A FIFO with no writer would block a plain open.
            fs::remove_file(folder.page()).unwrap();
            let made = Command::new("mkfifo").arg(folder.page()).status().unwrap();
            assert!(made.success());
            assert!(refusal(&folder).contains("it is not a regular file"));
        }
    }

    /// The refusal of a malformed checksum file reads the same after the wrapping of an error
    /// message, with a long absolute path: the format is in words (AUD-023-UI009).
    #[test]
    fn the_checksum_format_survives_wrapping() {
        let path =
            Path::new("/home/someone/a/rather/long/folder/name/of/the/tools").join(CHECKSUM_FILE);
        let message = format!("{} {MALFORMED}", style::shown_path(&path));
        let shown = style::error_lines_for_test(&message).join(" ");
        let words: Vec<&str> = shown.split_whitespace().collect();
        assert!(
            words.join(" ").contains(
                "the page's SHA-256, two spaces and its file name, or one space and * before the name"
            ),
            "{shown}"
        );
    }

    /// The menu's fast-mode entry needs the page as its checksum file names it: a missing or
    /// changed page, or a malformed file, gives the reason instead, and no file no entry
    /// (AUD-023-DOC008). `run` still refuses a page changed after the menu was built.
    #[test]
    fn the_fast_mode_is_offered_only_for_a_checked_page() {
        let digest = hex::encode(Sha256::digest(PAGE));
        let folder = TestFolder::new("offered");
        assert_eq!(checked_page_in(&folder.0).unwrap(), None);
        folder.write_checksum_file(&format!("{digest}  tool.html\n"));
        assert_eq!(checked_page_in(&folder.0).unwrap(), Some(folder.page()));
        fs::write(folder.page(), b"changed").unwrap();
        let changed = checked_page_in(&folder.0).unwrap_err().message;
        assert!(changed.contains("The page has changed"), "{changed}");
        assert!(load_checked_page(&folder.page()).is_err());
        fs::remove_file(folder.page()).unwrap();
        let missing = checked_page_in(&folder.0).unwrap_err().message;
        assert!(missing.contains("Cannot read"), "{missing}");
        folder.write_checksum_file("not a checksum line\n");
        let malformed = checked_page_in(&folder.0).unwrap_err().message;
        assert!(
            malformed.contains("must hold exactly one line"),
            "{malformed}"
        );
    }
}
