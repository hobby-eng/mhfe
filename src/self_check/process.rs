//! The parts of the command-line tool's self-test that check its own process: core dumps,
//! isolation and hidden input. The tool runs them (src/bin/mhfe) under these ids and labels; a
//! web page cannot, and the browser package's full self-check reports each as not available, with
//! the reason given here, beside the memory lock that [`crate::memory::LockProbe`] reports itself.

/// A part that checks the program's own process, with why a web page cannot check it.
#[derive(Clone, Copy, Debug)]
pub struct ProcessPart {
    pub id: &'static str,
    pub label: &'static str,
    /// Why a web page cannot check it: the detail of its outcome there, not available.
    pub in_browser: &'static str,
}

/// No core dumps, and on Linux no reading of the process's memory by other programs.
pub const CORE_DUMPS: ProcessPart = ProcessPart {
    id: "core-dumps",
    label: "Core dumps",
    in_browser: "the browser keeps its own crash reports, which a page cannot turn off",
};

/// The sandbox of a command that handles secrets: no network, no writes.
pub const ISOLATION: ProcessPart = ProcessPart {
    id: "isolation",
    label: "Isolation",
    in_browser: "a web page cannot sandbox itself or prove that it is offline",
};

/// The terminal's echo, switched off for a secret and read back.
pub const HIDDEN_INPUT: ProcessPart = ProcessPart {
    id: "hidden-input",
    label: "Hidden input",
    in_browser: "a web page has no terminal whose echo it could read back",
};

/// The process parts, in the order the command-line tool's report lists them.
pub const PROCESS_PARTS: [ProcessPart; 3] = [CORE_DUMPS, ISOLATION, HIDDEN_INPUT];
