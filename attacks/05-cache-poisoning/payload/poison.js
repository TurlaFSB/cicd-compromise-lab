// Benign stand-in for cache-poisoning payload.
//
// In a real attack, the PR author's build step writes a tampered file into
// a cached path (node_modules/ or dist/) before the cache is saved. When the
// privileged release workflow restores that cache and skips a clean rebuild,
// this file is executed as part of the published package.
//
// This lab version only writes a marker and prints a notice. It does not
// touch the network, read secrets, or modify anything outside the build dir.
// It exists to prove the restored-cache path is executed, nothing more.

const fs = require("fs");
const path = require("path");

const marker = path.join(__dirname, ".poison-marker");
fs.writeFileSync(
  marker,
  [
    "CACHE POISONING PROOF-OF-CONCEPT",
    "This file arrived via a cache entry written by fork-PR code and was",
    "restored, unverified, into a privileged release build.",
    `run: ${process.env.GITHUB_RUN_ID || "local"}`,
    `sha: ${process.env.GITHUB_SHA || "local"}`,
    "",
    "In a real compromise this code would run with the release job's",
    "NPM_TOKEN and GITHUB_TOKEN and ship inside the published artifact.",
  ].join("\n") + "\n"
);

console.log("[poison] executed from restored cache — integrity check absent");
