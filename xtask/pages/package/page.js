// The page of the package checks: it starts their module worker and keeps what the worker posts
// for `cargo xtask package-check`, which waits for self.mhfeCheck. The task gives CHECKS (the
// checks' module) and WORKER (xtask/pages/package/worker.js) in front of this script.
(() => {
  const results = [];
  const failures = [];
  const finish = () => {
    self.mhfeCheck = { mode: self.crossOriginIsolated ? "fast" : "standard", results, failures };
  };
  const urlOf = (text) => URL.createObjectURL(new Blob([text], { type: "text/javascript" }));
  const checks = urlOf(CHECKS);
  const entry = WORKER.replace("import(CHECKS_URL)", `import(${JSON.stringify(checks)})`);
  const worker = new Worker(urlOf(entry), { type: "module" });
  worker.onmessage = ({ data }) => {
    if (data.type === "line") {
      results.push(data.text);
      return;
    }
    if (data.type !== "done") failures.push(data.text);
    finish();
  };
  worker.onerror = (event) => {
    failures.push(`the checks' worker failed: ${event.message}`);
    finish();
  };
})();
