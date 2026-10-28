//! A client of WebDriver classic, the W3C protocol, for the browser checks: JSON over HTTP/1.1 to
//! a local chromedriver or geckodriver, with the few commands the checks need. A session opens a
//! page, runs an asynchronous script in it and ends.

use std::io::{BufRead, BufReader, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::{Failure, at};

/// How long a driver may take before it says it is ready.
const START_TIME: Duration = Duration::from_secs(30);
/// How long one command may take: a page's script may run for its whole timeout, ten minutes.
const COMMAND_TIME: Duration = Duration::from_secs(660);
/// How often a starting driver is asked whether it is ready.
const POLL_TIME: Duration = Duration::from_millis(100);

/// A driver that runs while this lives.
pub(crate) struct Driver {
    child: Child,
    port: u16,
    /// The file of the driver's own messages, which tell why a browser did not start.
    pub(crate) log: PathBuf,
}

/// A session of a driver: one browser, ended when this is dropped.
pub(crate) struct Session<'a> {
    driver: &'a Driver,
    id: String,
    /// What the browser says it is, its version among them.
    pub(crate) capabilities: Value,
}

impl Driver {
    /// Starts `program` on a free loopback port and waits until it says it is ready. Its messages
    /// go to a log in `work`. The browsers keep their profiles in the system's temporary folder:
    /// Chrome's singleton socket there must fit the 108 bytes of a Unix socket's path, which a
    /// folder in a deep checkout does not.
    pub(crate) fn start(program: &Path, work: &Path) -> Result<Self, Failure> {
        let name = program
            .file_name()
            .unwrap_or(program.as_os_str())
            .to_string_lossy();
        let log = work.join(format!("{name}.log"));
        let messages = std::fs::File::create(&log).map_err(|error| at(&log, error))?;
        let errors = messages.try_clone().map_err(|error| at(&log, error))?;
        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map_err(|error| Failure(format!("no free loopback port: {error}")))?
            .port();
        let child = Command::new(program)
            .arg(format!("--port={port}"))
            .stdin(Stdio::null())
            .stdout(messages)
            .stderr(errors)
            .spawn()
            .map_err(|error| at(program, error))?;
        let driver = Self { child, port, log };
        let started = Instant::now();
        while started.elapsed() < START_TIME {
            if driver
                .command("GET", "/status", None)
                .is_ok_and(|status| status["ready"] == true)
            {
                return Ok(driver);
            }
            thread::sleep(POLL_TIME);
        }
        Err(Failure(format!(
            "{} did not get ready; its messages are in {}",
            program.display(),
            driver.log.display()
        )))
    }

    /// Opens a session with a browser that matches `capabilities`.
    pub(crate) fn session(&self, capabilities: Value) -> Result<Session<'_>, Failure> {
        let request = json!({ "capabilities": { "alwaysMatch": capabilities } });
        let value = self.command("POST", "/session", Some(&request))?;
        let id = value["sessionId"]
            .as_str()
            .ok_or_else(|| Failure("the driver opened no session".to_owned()))?;
        Ok(Session {
            driver: self,
            id: id.to_owned(),
            capabilities: value["capabilities"].clone(),
        })
    }

    /// Sends one command and gives its value, or the driver's error as a failure.
    fn command(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, Failure> {
        let failed = |error: &dyn std::fmt::Display| Failure(format!("{method} {path}: {error}"));
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).map_err(|e| failed(&e))?;
        stream
            .set_read_timeout(Some(COMMAND_TIME))
            .map_err(|e| failed(&e))?;
        let body = body.map(Value::to_string).unwrap_or_default();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\
             Content-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            self.port,
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| failed(&e))?;
        let body = response_body(&mut BufReader::new(stream)).map_err(|error| failed(&error))?;
        let value: Value = serde_json::from_slice(&body)
            .map_err(|error| failed(&format!("the response is not JSON: {error}")))?;
        match value["value"]["error"].as_str() {
            Some(error) => Err(failed(&format!("{error}: {}", value["value"]["message"]))),
            None => Ok(value["value"].clone()),
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // The driver may have ended already; then there is nothing to stop.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Session<'_> {
    /// Opens `url` and waits until it has loaded.
    pub(crate) fn navigate(&self, url: &str) -> Result<(), Failure> {
        let path = format!("/session/{}/url", self.id);
        self.driver
            .command("POST", &path, Some(&json!({ "url": url })))
            .map(drop)
    }

    /// Runs `script` in the page as the body of an asynchronous function, whose last argument it
    /// calls with its result, and gives that result.
    pub(crate) fn execute_async(&self, script: &str) -> Result<Value, Failure> {
        let path = format!("/session/{}/execute/async", self.id);
        let request = json!({ "script": script, "args": [] });
        self.driver.command("POST", &path, Some(&request))
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        // A browser that has gone already has no session left to end.
        let _ = self
            .driver
            .command("DELETE", &format!("/session/{}", self.id), None);
    }
}

/// The body of the HTTP response that `reader` gives: as long as its Content-Length says, or else
/// up to the end. A driver may keep the connection open after the body, so the length counts.
fn response_body(reader: &mut impl BufRead) -> Result<Vec<u8>, String> {
    let failed = |error: std::io::Error| error.to_string();
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_err(failed)? == 0 || line == "\r\n" {
            break;
        }
        head.push_str(&line.to_ascii_lowercase());
    }
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|length| length.trim().parse::<usize>().ok());
    let mut body = Vec::new();
    match length {
        Some(length) => {
            body.resize(length, 0);
            reader.read_exact(&mut body).map_err(failed)?;
        }
        None => {
            reader.read_to_end(&mut body).map_err(failed)?;
        }
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_response_body_is_read_by_its_length_or_to_the_end() {
        let body = |response: &[u8]| response_body(&mut &response[..]);
        let sized = b"HTTP/1.1 200 OK\r\nContent-Length:14\r\n\r\n{\"value\":true}and more";
        assert_eq!(body(sized).ok(), Some(b"{\"value\":true}".to_vec()));
        let open_ended = b"HTTP/1.1 200 OK\r\n\r\nto the end";
        assert_eq!(body(open_ended).ok(), Some(b"to the end".to_vec()));
        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort";
        assert!(body(short).is_err());
    }
}
