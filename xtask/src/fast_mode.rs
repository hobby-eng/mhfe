//! `cargo xtask fast-mode`: the checks of `packaging/mhfe-fast-mode.py`, the Python version of
//! `mhfe serve`, which a computer with Python but without the mhfe program runs.
//!
//! They run the launcher with `python3` as a person does and talk to it over 127.0.0.1, so that
//! what is checked is what it does: the page and its headers, the refusals of other hosts, paths,
//! methods and malformed requests, a slow client and an endless request head, the connection
//! limit, every refusal of the checksum file, escaped names and arguments, and the page next to
//! the script without arguments. The cases are those of the tests in `src/bin/mhfe/serve.rs`, so
//! that both launchers behave alike. Its security headers, its checksum file's name and its six
//! limits are deliberate copies of serve.rs, as the script cannot import it: they are compared
//! with that file here. The launcher's deadlines are its real ten seconds, so the run takes about
//! as long. Its folders are made in `target/xtask-fast-mode/` and removed afterwards.

use std::ffi::OsStr;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::{Failure, at, wasm};

const SCRIPT: &str = "packaging/mhfe-fast-mode.py";
const SERVE: &str = "src/bin/mhfe/serve.rs";
const PAGE: &[u8] = b"<!doctype html><title>tool</title>";
/// The SHA-256 of PAGE, as `sha256sum --text` and `--binary` print it (GNU coreutils).
const PAGE_SHA256: &str = "a760013b4e475f909edfdcb6e7f228ecd5536cca669741ce43972ecffd5b6f6c";
/// The launcher's deadline for a request head and for its answer, in seconds, and its limit on
/// connections answered at once (compared with serve.rs below).
const DEADLINE: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 16;
/// The exit code of a refused start, as the mhfe program uses it.
const INVALID_INPUT: i32 = 2;
/// The launcher's limits by their names in the script and in serve.rs.
const LIMITS: [&str; 6] = [
    "MAX_REQUEST_HEAD",
    "REQUEST_DEADLINE",
    "RESPONSE_DEADLINE",
    "MAX_CONNECTIONS",
    "MAX_CHECKSUM_FILE",
    "MAX_PAGE",
];

/// A failure of the launcher's checks, named as such.
fn ensure(condition: bool, what: impl FnOnce() -> String) -> Result<(), Failure> {
    crate::ensure(condition, || format!("fast mode: {}", what()))
}

pub(crate) fn run(root: &Path) -> Result<(), Failure> {
    let script = root.join(SCRIPT);
    let launcher = wasm::text(&script)?;
    let serve = wasm::text(&root.join(SERVE))?;
    check_copies(&launcher, &serve)?;
    let folder = root.join("target/xtask-fast-mode");
    // A folder left by a run that was stopped is replaced.
    let _ = fs::remove_dir_all(&folder);
    fs::create_dir_all(&folder).map_err(|error| at(&folder, error))?;
    let result = checks(&script, &folder, &serve);
    let _ = fs::remove_dir_all(&folder);
    result?;
    println!("The fast-mode launcher behaves as mhfe serve.");
    Ok(())
}

fn checks(script: &Path, folder: &Path, serve: &str) -> Result<(), Failure> {
    let page = folder.join("tool.html");
    fs::write(&page, PAGE).map_err(|error| at(&page, error))?;
    write_checksum_file(folder, &format!("{PAGE_SHA256}  tool.html\n"))?;
    // Two launchers, so that the connection limit starts with every slot free.
    let mut first = Launcher::start(script, &page)?;
    let mut second = Launcher::start(script, &page)?;
    let served = routing(&first, serve).and_then(|()| request_head_limits(&first));
    let limited = connection_limit(&second);
    first.stop();
    second.stop();
    served?;
    limited?;
    checksum_file(script, folder, &page)?;
    names_and_arguments(script, folder, serve)?;
    next_to_the_script(script, folder)
}

/// The security headers, the checksum file's name and the limits are those of serve.rs.
fn check_copies(launcher: &str, serve: &str) -> Result<(), Failure> {
    for name in LIMITS {
        let script = value_after(launcher, &format!("\n{name} = "));
        let rust = value_after(serve, &format!("const {name}: "))
            .and_then(|typed| typed.split_once("= ").map(|(_, value)| value));
        let (script, rust) = (script.and_then(number), rust.and_then(number));
        ensure(script.is_some() && script == rust, || {
            format!("{name} is {script:?} in {SCRIPT} and {rust:?} in {SERVE}")
        })?;
    }
    let name = value_after(serve, "const CHECKSUM_FILE: &str = ");
    let same = name.is_some_and(|name| launcher.contains(&format!("\nCHECKSUM_FILE = {name}")));
    ensure(same, || {
        format!("the checksum file of {SCRIPT} is not that of {SERVE}")
    })?;
    println!("fast mode: its limits and its checksum file's name are those of mhfe serve");
    Ok(())
}

/// The rest of the line after `prefix`, without a trailing `;`.
fn value_after<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = &text[text.find(prefix)? + prefix.len()..];
    Some(rest.lines().next()?.trim().trim_end_matches(';'))
}

/// The value of `16 * 1024`, `10.0` or `Duration::from_secs(10)`.
fn number(expression: &str) -> Option<u64> {
    let inner = expression
        .strip_prefix("Duration::from_secs(")
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or(expression);
    inner.split('*').try_fold(1_u64, |product, factor| {
        let factor = factor.trim();
        let factor = factor.strip_suffix(".0").unwrap_or(factor);
        product.checked_mul(factor.parse().ok()?)
    })
}

fn write_checksum_file(folder: &Path, text: &str) -> Result<(), Failure> {
    let path = folder.join("mhfe-fast-mode.sha256");
    fs::write(&path, text).map_err(|error| at(&path, error))
}

/// The launcher started with python3, `--no-browser` and `arguments`, its standard error read
/// through a pipe.
fn launch(script: &Path, arguments: &[&OsStr]) -> Result<Child, Failure> {
    Command::new("python3")
        .arg(script)
        .arg("--no-browser")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Failure(format!("python3 did not start: {error}")))
}

/// A launcher serving a page, with the port it announced.
struct Launcher {
    child: Child,
    port: u16,
}

impl Launcher {
    fn start(script: &Path, page: &Path) -> Result<Self, Failure> {
        let mut child = launch(script, &[page.as_os_str()])?;
        let stderr = child.stderr.take();
        let (lines, received) = mpsc::channel();
        thread::spawn(move || {
            for line in stderr
                .map(BufReader::new)
                .into_iter()
                .flat_map(BufRead::lines)
            {
                if lines.send(line.unwrap_or_default()).is_err() {
                    break;
                }
            }
        });
        let address = "Open http://127.0.0.1:";
        while let Ok(line) = received.recv_timeout(Duration::from_secs(10)) {
            if let Some(port) = line
                .strip_prefix(address)
                .and_then(|rest| rest.split('/').next())
                .and_then(|port| port.parse().ok())
            {
                return Ok(Self { child, port });
            }
        }
        let _ = child.kill();
        Err(Failure(
            "fast mode: the launcher announced no address".to_owned(),
        ))
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn connect(&self) -> Result<TcpStream, Failure> {
        let connection = TcpStream::connect(("127.0.0.1", self.port))
            .map_err(|error| Failure(format!("fast mode: no connection: {error}")))?;
        connection
            .set_read_timeout(Some(DEADLINE + Duration::from_secs(5)))
            .map_err(|error| Failure(error.to_string()))?;
        Ok(connection)
    }

    /// What the launcher answers to `head`, read until it closes the connection.
    fn reply(&self, head: &[u8]) -> Result<Vec<u8>, Failure> {
        let mut connection = self.connect()?;
        // The launcher may close before all of a long head is sent.
        let _ = connection.write_all(head);
        let mut reply = Vec::new();
        let _ = connection.read_to_end(&mut reply);
        Ok(reply)
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn request(method: &str, target: &str, host: &str) -> Vec<u8> {
    format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n\r\n").into_bytes()
}

fn status_line(reply: &[u8]) -> String {
    let end = reply
        .windows(2)
        .position(|pair| pair == b"\r\n")
        .unwrap_or(reply.len());
    String::from_utf8_lossy(&reply[..end]).into_owned()
}

fn expect_status(launcher: &Launcher, head: &[u8], status: &str) -> Result<(), Failure> {
    let reply = launcher.reply(head)?;
    let got = status_line(&reply);
    ensure(got == status, || {
        format!(
            "{:?} got {got:?}, not {status:?}",
            String::from_utf8_lossy(head)
        )
    })
}

/// The page with every header of serve.rs, HEAD without the body, and the refusals of other
/// hosts, paths, methods and malformed heads.
fn routing(launcher: &Launcher, serve: &str) -> Result<(), Failure> {
    let host = launcher.host();
    let reply = launcher.reply(&request("GET", "/", &host))?;
    ensure(status_line(&reply) == "HTTP/1.1 200 OK", || {
        "the page was not served".to_owned()
    })?;
    ensure(reply.ends_with(PAGE), || {
        "the page was not the body".to_owned()
    })?;
    let text = String::from_utf8_lossy(&reply);
    let headers = security_headers(serve);
    ensure(headers.len() == 7, || {
        format!("{SERVE} holds {} security headers", headers.len())
    })?;
    for (name, value) in
        std::iter::once(("Content-Type", "text/html; charset=utf-8")).chain(headers.iter().copied())
    {
        ensure(text.contains(&format!("{name}: {value}\r\n")), || {
            format!("the page came without {name}: {value}")
        })?;
    }
    // And no header beyond those and the ones every answer has.
    let head_end = text.find("\r\n\r\n").unwrap_or(text.len());
    let extra: Vec<&str> = text[..head_end]
        .split("\r\n")
        .skip(1)
        .filter(|line| {
            let name = line.split(':').next().unwrap_or_default();
            !["Content-Type", "Content-Length", "Connection"].contains(&name)
                && !headers.iter().any(|(known, _)| *known == name)
        })
        .collect();
    ensure(extra.is_empty(), || {
        format!("the page came with headers serve.rs does not send: {extra:?}")
    })?;
    let head = launcher.reply(&request("HEAD", "/", &host))?;
    let length = format!("Content-Length: {}\r\n", PAGE.len());
    ensure(
        status_line(&head) == "HTTP/1.1 200 OK"
            && String::from_utf8_lossy(&head).contains(&length)
            && head.ends_with(b"\r\n\r\n"),
        || "HEAD did not send the headers alone".to_owned(),
    )?;
    let port = launcher.port;
    // Against DNS rebinding: only the address the launcher serves, with its port.
    let others = [
        format!("localhost:{port}"),
        "127.0.0.1".to_owned(),
        format!("127.0.0.1:{}", port.wrapping_add(1)),
        format!("evil.example:{port}"),
        String::new(),
    ];
    for other in others {
        expect_status(
            launcher,
            &request("GET", "/", &other),
            "HTTP/1.1 403 Forbidden",
        )?;
    }
    expect_status(
        launcher,
        b"GET / HTTP/1.1\r\n\r\n",
        "HTTP/1.1 403 Forbidden",
    )?;
    let two_hosts = format!("GET / HTTP/1.1\r\nHost: {host}\r\nHost: {host}\r\n\r\n");
    expect_status(launcher, two_hosts.as_bytes(), "HTTP/1.1 403 Forbidden")?;
    for target in ["/index.html", "/../", "//", "/?x=1", "*"] {
        expect_status(
            launcher,
            &request("GET", target, &host),
            "HTTP/1.1 404 Not Found",
        )?;
    }
    for method in ["POST", "PUT", "DELETE", "OPTIONS", "get"] {
        expect_status(
            launcher,
            &request(method, "/", &host),
            "HTTP/1.1 405 Method Not Allowed",
        )?;
    }
    for malformed in ["GET /", "GET / HTTP/2\r\nHost: x", "GET  / HTTP/1.1"] {
        let head = format!("{malformed}\r\n\r\n");
        expect_status(launcher, head.as_bytes(), "HTTP/1.1 400 Bad Request")?;
    }
    println!(
        "fast mode: the page with every header of mhfe serve; other hosts, paths, methods refused"
    );
    Ok(())
}

/// The (name, value) pairs of serve.rs's SECURITY_HEADERS.
fn security_headers(serve: &str) -> Vec<(&str, &str)> {
    let Some(start) = serve.find("const SECURITY_HEADERS") else {
        return Vec::new();
    };
    let block = &serve[start..];
    let block = &block[..block.find("];").unwrap_or(block.len())];
    block
        .lines()
        .filter_map(|line| line.trim().strip_prefix("(\"")?.strip_suffix("\"),"))
        .filter_map(|pair| pair.split_once("\", \""))
        .collect()
}

/// A client that sends its head one byte at a time holds up no one and is dropped at the
/// deadline; a head without end is refused.
fn request_head_limits(launcher: &Launcher) -> Result<(), Failure> {
    let slow = launcher.connect()?;
    let mut dripping = slow
        .try_clone()
        .map_err(|error| Failure(error.to_string()))?;
    thread::spawn(move || {
        for byte in b"GET / HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
            if dripping.write_all(&[*byte]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    let started = Instant::now();
    let reply = launcher.reply(&request("GET", "/", &launcher.host()))?;
    ensure(status_line(&reply) == "HTTP/1.1 200 OK", || {
        "a slow client held up the page".to_owned()
    })?;
    ensure(started.elapsed() < Duration::from_millis(400), || {
        "the page came late".to_owned()
    })?;
    let mut rest = Vec::new();
    let _ = (&slow).read_to_end(&mut rest);
    let held = started.elapsed();
    ensure(
        held >= DEADLINE - Duration::from_secs(1) && held < DEADLINE + Duration::from_secs(2),
        || format!("the slow client was dropped after {held:?}, not at the deadline"),
    )?;
    let mut endless = b"GET / HTTP/1.1\r\n".to_vec();
    endless.extend(b"X-Filler: a\r\n".repeat(5000));
    let reply = launcher.reply(&endless)?;
    ensure(status_line(&reply) == "HTTP/1.1 400 Bad Request", || {
        format!("an endless head got {:?}", status_line(&reply))
    })?;
    println!("fast mode: a slow client neither holds up others nor outlives the deadline");
    println!("fast mode: an endless request head is refused");
    Ok(())
}

/// Beyond MAX_CONNECTIONS clients that send nothing, a connection is closed at once.
fn connection_limit(launcher: &Launcher) -> Result<(), Failure> {
    let idle: Vec<TcpStream> = (0..MAX_CONNECTIONS)
        .map(|_| launcher.connect())
        .collect::<Result<_, _>>()?;
    thread::sleep(Duration::from_millis(100));
    let mut extra = launcher.connect()?;
    extra
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| Failure(error.to_string()))?;
    let started = Instant::now();
    let mut byte = [0_u8; 1];
    let read = extra.read(&mut byte);
    ensure(
        matches!(read, Ok(0)) || read.is_err() && started.elapsed() < Duration::from_secs(2),
        || "the extra connection got an answer".to_owned(),
    )?;
    ensure(started.elapsed() < Duration::from_millis(400), || {
        "the extra connection was not closed at once".to_owned()
    })?;
    drop(idle);
    println!("fast mode: connections beyond the limit are closed at once");
    Ok(())
}

/// What the launcher says and its exit code when started with `arguments` and refused; a failure
/// when it serves instead.
fn refusal(script: &Path, arguments: &[&str]) -> Result<(i32, String), Failure> {
    let arguments: Vec<&OsStr> = arguments.iter().map(OsStr::new).collect();
    let mut child = launch(script, &arguments)?;
    let started = Instant::now();
    while child
        .try_wait()
        .map_err(|error| Failure(error.to_string()))?
        .is_none()
    {
        if started.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            return Err(Failure(format!(
                "fast mode: {arguments:?} was served, not refused"
            )));
        }
        thread::sleep(Duration::from_millis(20));
    }
    let output = child
        .wait_with_output()
        .map_err(|error| Failure(error.to_string()))?;
    let code = output.status.code().unwrap_or(-1);
    Ok((code, String::from_utf8_lossy(&output.stderr).into_owned()))
}

fn expect_refused(script: &Path, page: &Path, says: &str, case: &str) -> Result<(), Failure> {
    let (code, text) = refusal(script, &[&page.to_string_lossy()])?;
    ensure(code == INVALID_INPUT && text.contains(says), || {
        format!("{case}: exit code {code}, {text:?}, not {says:?}")
    })
}

/// The page is served only when the checksum file next to it names it with its SHA-256.
fn checksum_file(script: &Path, folder: &Path, page: &Path) -> Result<(), Failure> {
    for line in [
        format!("{PAGE_SHA256}  tool.html\n"),
        format!("{}  tool.html\n", PAGE_SHA256.to_uppercase()),
        format!("{PAGE_SHA256} *tool.html\n"),
    ] {
        write_checksum_file(folder, &line)?;
        let mut launcher = Launcher::start(script, page)?;
        launcher.stop();
    }
    // Only one marker is removed: a further "*" belongs to the name, which then differs.
    for line in [
        format!("{PAGE_SHA256}  *tool.html\n"),
        format!("{PAGE_SHA256} **tool.html\n"),
    ] {
        write_checksum_file(folder, &line)?;
        expect_refused(script, page, "names *tool.html, not tool.html", &line)?;
    }
    let _ = fs::remove_file(folder.join("mhfe-fast-mode.sha256"));
    expect_refused(
        script,
        page,
        "There is no readable mhfe-fast-mode.sha256",
        "none",
    )?;
    let zeros = "00".repeat(32);
    write_checksum_file(folder, &format!("{zeros}  tool.html\n"))?;
    expect_refused(
        script,
        page,
        "but mhfe-fast-mode.sha256 expects",
        "another digest",
    )?;
    write_checksum_file(folder, &format!("{PAGE_SHA256}  other.html\n"))?;
    expect_refused(
        script,
        page,
        "names other.html, not tool.html",
        "another name",
    )?;
    let digest = PAGE_SHA256;
    let short = &digest[..63];
    // A deliberate copy of the malformed lines of serve.rs's tests, so that both launchers refuse
    // them alike.
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
        format!("{short}  tool.html\n"),
        format!("{short}g *tool.html\n"),
        // The control-character cases of serve.rs.
        format!("{digest}  x\u{1b}]0;TITLE\u{7}\u{1b}[2Jy.html\n"),
        format!("{digest}  x\u{9b}2Jy.html\n"),
        format!("{digest}  x\u{7f}y.html\n"),
        format!("{digest}  tool.html\u{1f}\n"),
        format!("{digest}  to\u{1b}ol.html\n"),
    ] {
        write_checksum_file(folder, &malformed)?;
        expect_refused(
            script,
            page,
            "must hold exactly one line",
            &format!("{malformed:?}"),
        )?;
    }
    expect_refused(
        script,
        page,
        "nothing was served",
        "a malformed checksum file",
    )?;
    let path = folder.join("mhfe-fast-mode.sha256");
    fs::write(&path, b"\xff\xfe  tool.html\n").map_err(|error| at(&path, error))?;
    expect_refused(script, page, "There is no readable", "not UTF-8")?;
    write_checksum_file(folder, &format!("{PAGE_SHA256}  tool.html\n"))?;
    println!("fast mode: served only when its checksum file names the page with its SHA-256");
    Ok(())
}

/// A folder name with an OSC 52 sequence, which would set the clipboard, is shown escaped as
/// serve.rs escapes it, and a mistyped argument is not repeated.
fn names_and_arguments(script: &Path, folder: &Path, serve: &str) -> Result<(), Failure> {
    let odd = folder.join("x\u{1b}]52;c;QUFB\u{7}y");
    fs::create_dir_all(&odd).map_err(|error| at(&odd, error))?;
    let (code, text) = refusal(script, &[&odd.join("tool.html").to_string_lossy()])?;
    let controls = text
        .trim_end()
        .chars()
        .any(|char| char.is_control() && char != '\n');
    ensure(
        code == INVALID_INPUT && text.contains("There is no readable") && !controls,
        || format!("a folder with a control sequence: {text:?}"),
    )?;
    ensure(text.contains("x\\u{1b}]52;c;QUFB\\u{7}y"), || {
        format!("the folder's name was not escaped: {text:?}")
    })?;
    // The input of serve.rs's test a_shown_path_holds_no_control_character, shown as that test
    // expects mhfe serve to show it.
    let titled = folder.join("x\u{1b}]0;TITLE\u{7}y");
    fs::create_dir_all(&titled).map_err(|error| at(&titled, error))?;
    let (_, text) = refusal(script, &[&titled.join("tool.html").to_string_lossy()])?;
    let escaped = "x\\u{1b}]0;TITLE\\u{7}y";
    let in_serve = serve.contains(&escaped.replace('\\', "\\\\"));
    ensure(text.contains(escaped) && in_serve, || {
        format!("the folder's name is not shown as serve.rs's test expects: {text:?}")
    })?;
    let (code, text) = refusal(script, &["--x\u{1b}]52;c;QUFB\u{7}", "--\u{9b}2J"])?;
    ensure(
        code == INVALID_INPUT
            && !text.contains("QUFB")
            && text.contains("the arguments cannot be used"),
        || format!("a mistyped argument: exit code {code}, {text:?}"),
    )?;
    println!(
        "fast mode: names escaped as mhfe serve escapes them; a mistyped argument not repeated"
    );
    Ok(())
}

/// Without arguments, the page named in the checksum file next to the script; refused, with the
/// invalid-input exit code, when there is no checksum file or it does not match.
fn next_to_the_script(script: &Path, folder: &Path) -> Result<(), Failure> {
    let alone = folder.join("alone");
    fs::create_dir_all(&alone).map_err(|error| at(&alone, error))?;
    let copy: PathBuf = alone.join("mhfe-fast-mode.py");
    fs::copy(script, &copy).map_err(|error| at(&copy, error))?;
    let page = alone.join("tool.html");
    fs::write(&page, PAGE).map_err(|error| at(&page, error))?;
    let (code, text) = refusal(&copy, &[])?;
    ensure(
        code == INVALID_INPUT && text.contains("next to this script"),
        || format!("no checksum file: exit code {code}, {text:?}"),
    )?;
    write_checksum_file(&alone, &format!("{}  tool.html\n", "00".repeat(32)))?;
    let (code, text) = refusal(&copy, &[])?;
    ensure(code == INVALID_INPUT && text.contains("expects"), || {
        format!("a wrong checksum: exit code {code}, {text:?}")
    })?;
    println!("fast mode: without arguments, the page next to the script, or a refusal");
    Ok(())
}
