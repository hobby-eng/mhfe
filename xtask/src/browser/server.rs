//! The page server of the fast mode: one page from 127.0.0.1 with the headers that make it
//! cross-origin isolated, as `mhfe serve` gives them. It records the request line of every
//! request, so that a check sees whether the page asked for anything but itself; anything else is
//! answered with 404.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use crate::Failure;

/// The headers of the page: COOP and COEP make it cross-origin isolated.
const PAGE_HEADERS: &str = "Content-Type: text/html; charset=utf-8\r\n\
                            Cross-Origin-Opener-Policy: same-origin\r\n\
                            Cross-Origin-Embedder-Policy: require-corp\r\n\
                            Cache-Control: no-store\r\n";
/// How long a connection may take to send its request.
const REQUEST_TIME: Duration = Duration::from_secs(10);
/// The most bytes of a request's head that are read.
const MOST_HEAD_BYTES: usize = 16 * 1024;

/// A server that runs on its own thread as long as the program.
pub(crate) struct PageServer {
    /// The loopback port it listens on.
    pub(crate) port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

impl PageServer {
    /// Serves `page` at `/` on a free loopback port.
    pub(crate) fn start(page: Vec<u8>) -> Result<Self, Failure> {
        let failed = |error: std::io::Error| Failure(format!("the page server: {error}"));
        let listener = TcpListener::bind("127.0.0.1:0").map_err(failed)?;
        let port = listener.local_addr().map_err(failed)?.port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let page: Arc<[u8]> = page.into();
        // A thread for each connection, so that one a browser opens ahead and never uses does not
        // hold up the page's request.
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (page, recorded) = (Arc::clone(&page), Arc::clone(&recorded));
                thread::spawn(move || answer(stream, &page, &recorded));
            }
        });
        Ok(Self { port, requests })
    }

    /// The request lines received so far, in their order.
    pub(crate) fn requests(&self) -> Vec<String> {
        // A thread that panicked while it held the list leaves it as complete as it was.
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Reads one request from `stream`, records its first line and answers it.
fn answer(mut stream: TcpStream, page: &[u8], requests: &Mutex<Vec<String>>) {
    if stream.set_read_timeout(Some(REQUEST_TIME)).is_err() {
        return;
    }
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") && head.len() < MOST_HEAD_BYTES {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    let line = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    let reply = if line.starts_with("GET / ") {
        let head = format!(
            "HTTP/1.1 200 OK\r\n{PAGE_HEADERS}Content-Length: {}\r\n",
            page.len()
        );
        [
            format!("{head}Connection: close\r\n\r\n").into_bytes(),
            page.to_vec(),
        ]
        .concat()
    } else {
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
    };
    // A browser may open a connection ahead and close it without a request: that is none.
    if !line.is_empty() {
        requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
    }
    // A client that has gone away misses the answer; the recorded request still counts.
    let _ = stream.write_all(&reply);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(port: u16, request: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn the_page_is_served_isolated_and_every_request_is_recorded() {
        let server = PageServer::start(b"<p>page</p>".to_vec()).unwrap();
        let page = get(server.port, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(page.starts_with("HTTP/1.1 200 OK\r\n") && page.ends_with("\r\n\r\n<p>page</p>"));
        assert!(page.contains("Cross-Origin-Embedder-Policy: require-corp\r\n"));
        let other = get(
            server.port,
            "GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert!(other.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert_eq!(
            server.requests(),
            ["GET / HTTP/1.1", "GET /favicon.ico HTTP/1.1"]
        );
    }
}
