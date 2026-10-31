// The module worker that runs the package checks: it posts each line they print, then whether they
// passed, and anything they throw or leave unhandled. The page puts the object URL of the checks'
// module in the import below.

console.log = (...values) => postMessage({ type: "line", text: values.join(" ") });
// The checks were written for Node.js, which has no crossOriginIsolated: they set it to stand for
// an isolated page and delete it again. This worker's own, true in this page, would answer instead.
for (let scope = globalThis; scope !== null; scope = Object.getPrototypeOf(scope)) {
  delete scope.crossOriginIsolated;
}
// Firefox leaves the message out of a stack.
const description = (error) => `${error}\n${error?.stack ?? ""}`;
const report = (text) => postMessage({ type: "event", text });
self.addEventListener("unhandledrejection", (event) => {
  report(`a rejection without a handler: ${description(event.reason)}`);
});
self.addEventListener("error", (event) => {
  report(`an uncaught error: ${description(event.error ?? event.message)}`);
});
try {
  await import(CHECKS_URL);
  postMessage({ type: "done" });
} catch (error) {
  postMessage({ type: "failed", text: description(error) });
}
