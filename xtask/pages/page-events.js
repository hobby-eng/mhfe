// The page's event recorder, its first script, before its module: it records what the page
// throws, what it rejects without a handler and what its Content-Security-Policy blocks, so that a
// check that stops is seen at once and none of these passes unnoticed.
self.mhfePageEvents = [];
addEventListener("error", (event) => self.mhfePageEvents.push(`uncaught error: ${event.message}`));
addEventListener(
  "unhandledrejection",
  (event) => self.mhfePageEvents.push(`unhandled rejection: ${event.reason}`),
);
addEventListener(
  "securitypolicyviolation",
  (event) =>
    self.mhfePageEvents.push(
      `blocked by the policy: ${event.violatedDirective} ${event.blockedURI}`,
    ),
);
