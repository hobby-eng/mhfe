//! `cargo xtask browsers`: the browser package in real browsers, the pinned Chrome for Testing and
//! Firefox, driven through WebDriver (`browser/webdriver.rs`). `scripts/verify-browser-package.mjs`
//! checks the same code with a stand-in worker; this check adds what only a browser does: Blob
//! workers under the Content-Security-Policy of the offline wallet tools, the transfer of secrets
//! to them, the threaded Argon2 build in a cross-origin isolated page, cancellation and the page's
//! failing callbacks. Each browser opens the check page (`browser/page.rs`) twice: as a file
//! (standard mode) and from the page server with the isolation headers (fast mode,
//! `browser/server.rs`), as `mhfe serve` gives them.
//!
//! The task prints the page's results and fails on any failure, on any event that the page's
//! event recorder caught (an uncaught error, a rejection without a handler, a policy violation),
//! and in fast mode on any request but the page's own and the browser's own favicon. A worker
//! reports a policy violation in its own scope, where the recorder does not listen: the policy
//! still blocks the request, and `cargo xtask wasm verify` refuses network code in every script
//! before this check runs.
//!
//! MHFE_BROWSERS names the folder of the pinned browsers and drivers, each in a folder named after
//! it and its version, as CI's browser step unpacks the archives it checks by their SHA-256.

mod page;
mod server;
mod webdriver;

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::{Failure, at};
use server::PageServer;
use webdriver::Driver;

/// The pinned Chrome for Testing and its chromedriver.
const CHROME: &str = "155.0.8059.79";
/// The pinned Firefox.
const FIREFOX: &str = "158.0";
/// The pinned geckodriver.
const GECKODRIVER: &str = "0.37.1";
/// How long the page's script may run, in milliseconds. The page's other checks take under a
/// minute; each of its two drawings of a phrase that passes the wallet check takes about 65,536
/// BIP39 seeds on average, half a minute on eight workers, but the number is random: more than N
/// times the average happens about once in e^N drawings. Ten minutes leave room for eight times
/// the average of both together, which two drawings exceed about once in 500,000 pages
/// (e^-16 x 17), so a page that times out has stopped, not drawn long.
const SCRIPT_TIMEOUT_MS: u64 = 600_000;
/// The folder of the page and of the drivers' logs, from the root.
const WORK: &str = "target/browser-check";
/// The page as the standard mode opens it, in WORK.
const PAGE_FILE: &str = "reduced-cost.html";
/// The requests of the fast mode that are the page and the browser's own favicon.
const OWN_REQUESTS: [&str; 2] = ["GET / HTTP/1.1", "GET /favicon.ico HTTP/1.1"];
/// The script that waits until the page's checks have ended or its event recorder caught one.
const WAIT: &str = "const done = arguments[arguments.length - 1];\n\
                    const poll = () =>\n  \
                    self.mhfeCheck !== undefined || self.mhfePageEvents.length > 0\n    \
                    ? done({ check: self.mhfeCheck ?? null, events: self.mhfePageEvents })\n    \
                    : setTimeout(poll, 100);\npoll();";

/// A browser that the checks run in.
#[derive(Clone, Copy)]
enum Browser {
    Chrome,
    Firefox,
}

impl Browser {
    /// Its name, as the reports give it.
    fn name(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Firefox => "Firefox",
        }
    }

    /// Its driver program and the capabilities of a headless session, from `folder`, which holds
    /// the pinned browsers.
    fn driver_and_capabilities(self, folder: &Path) -> (PathBuf, Value) {
        let path = |relative: String| folder.join(relative).to_string_lossy().into_owned();
        let timeouts = json!({ "script": SCRIPT_TIMEOUT_MS });
        match self {
            Self::Chrome => (
                folder.join(format!(
                    "chromedriver-{CHROME}/chromedriver-linux64/chromedriver"
                )),
                json!({
                    "browserName": "chrome",
                    "goog:chromeOptions": {
                        "binary": path(format!("chrome-{CHROME}/chrome-linux64/chrome")),
                        // The unpacked Chrome for Testing has no AppArmor profile, and Ubuntu
                        // 24.04 and later can refuse it the user namespaces that its sandbox
                        // needs, as on CI runners: it runs without one, as Playwright ran it. The
                        // page is this repository's own, with public test data, opened as a file
                        // or served from 127.0.0.1.
                        "args": ["--headless=new", "--no-sandbox"],
                    },
                    "timeouts": timeouts,
                }),
            ),
            Self::Firefox => (
                folder.join(format!("geckodriver-{GECKODRIVER}/geckodriver")),
                json!({
                    "browserName": "firefox",
                    "moz:firefoxOptions": {
                        "binary": path(format!("firefox-{FIREFOX}/firefox/firefox")),
                        "args": ["-headless"],
                        // The browser's own favicon would be blocked by the page's policy and
                        // reported as a violation; the page loads no icon.
                        "prefs": { "browser.chrome.site_icons": false },
                    },
                    "timeouts": timeouts,
                }),
            ),
        }
    }
}

/// Runs the browser checks.
pub(crate) fn run(root: &Path) -> Result<(), Failure> {
    let folder = std::env::var_os("MHFE_BROWSERS")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            Failure("MHFE_BROWSERS must name the folder of the pinned browsers".to_owned())
        })?;
    let page = page::page(&root.join("dist"))?;
    let work = root.join(WORK);
    std::fs::create_dir_all(&work).map_err(|error| at(&work, error))?;
    let page_file = work.join(PAGE_FILE);
    std::fs::write(&page_file, &page).map_err(|error| at(&page_file, error))?;
    let server = PageServer::start(page.into_bytes())?;
    let mut failed = false;
    for browser in [Browser::Chrome, Browser::Firefox] {
        let (driver, capabilities) = browser.driver_and_capabilities(&folder);
        let driver = Driver::start(&driver, &work)?;
        let session = driver.session(capabilities).map_err(|failure| {
            Failure(format!(
                "{failure}; the driver's messages are in {}",
                driver.log.display()
            ))
        })?;
        let version = session.capabilities["browserVersion"]
            .as_str()
            .unwrap_or("?")
            .to_owned();
        let fast_url = format!("http://127.0.0.1:{}/", server.port);
        for (mode, url) in [("standard", file_url(&page_file)), ("fast", fast_url)] {
            let before = server.requests().len();
            session.navigate(&url)?;
            let outcome = session.execute_async(WAIT)?;
            let check = &outcome["check"];
            let mut failures = strings(&check["failures"]);
            if check.is_null() {
                failures.push("the page's checks did not finish".to_owned());
            }
            if check["mode"].as_str() != Some(mode) {
                failures.push(format!(
                    "the client ran in {} mode, not {mode}",
                    check["mode"]
                ));
            }
            failures.extend(strings(&outcome["events"]));
            let requests = server.requests();
            let stray = requests.get(before..).unwrap_or_default().iter();
            let stray = stray.filter(|request| !OWN_REQUESTS.contains(&request.as_str()));
            failures
                .extend(stray.map(|request| format!("a request reached the server: {request}")));
            println!("{} {version}, {mode} mode:", browser.name());
            for line in strings(&check["results"]) {
                println!("  {line}");
            }
            for failure in &failures {
                println!("  FAIL {failure}");
            }
            failed |= !failures.is_empty();
        }
    }
    if failed {
        return Err(Failure("The browser check failed.".to_owned()));
    }
    println!("The browser package passes its checks in Chrome and Firefox, in both modes.");
    Ok(())
}

/// The `file:` URL of `path`, its bytes percent-encoded but for the unreserved characters and
/// `/`, so that a `#`, `?` or `%` in a folder's name stays part of the path.
fn file_url(path: &Path) -> String {
    let mut url = String::from("file://");
    for &byte in path.as_os_str().as_encoded_bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            url.push(char::from(byte));
        } else {
            url.push_str(&format!("%{byte:02X}"));
        }
    }
    url
}

/// The strings of the JSON array `value`; anything else in it as its JSON text.
fn strings(value: &Value) -> Vec<String> {
    let items = value.as_array().map_or(&[][..], Vec::as_slice);
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map_or_else(|| item.to_string(), str::to_owned)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_url_keeps_every_character_of_its_path() {
        let url = file_url(Path::new("/home/u/mhfe#2/a b%c?.html"));
        assert_eq!(url, "file:///home/u/mhfe%232/a%20b%25c%3F.html");
    }
}
