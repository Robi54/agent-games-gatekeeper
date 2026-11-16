// End-to-end HTTP test for the ROBI-TRADER gatekeeper.
//
// Spawns the real server with a clearly labelled FAKE test secret
// (never a real platform secret), posts signed envelopes, and checks every
// behaviour the platform will exercise: preflight (both envelope spellings),
// all six decision outcomes, proof reuse, idempotent replay, bad/missing
// signatures, malformed tasks, and /health.
//
// Run: `npm test` (or `node test/e2e-test.mjs`). Exit 0 when all checks pass.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { hmacHex } from "../hmac.mjs";
import { GATEKEEPER_VK_HASH } from "../config.mjs";
import { verifyProof } from "../proof.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");

// Clearly labelled fake secret — the real platform secret is never here.
const TEST_SECRET = "test-secret-only-NOT-REAL-do-not-use-in-production";
const PORT = 3101;
const BASE_URL = `http://127.0.0.1:${PORT}`;

// Progress markers go to stderr (unbuffered) so a hang is diagnosable.
const dbg = (...a) => console.error("[e2e]", ...a);
// No fetch in this harness may hang forever: every call gets a hard timeout.
const FETCH_TIMEOUT_MS = 8000;

const VK = GATEKEEPER_VK_HASH;
const RECIPIENT = "0xde42000000000000000000000000000000009f01";

const INPUT_BASE = {
  registered_vk: VK,
  proof_vk: VK,
  minimum: 1000,
  public_balance: 1460,
  expiry_block: 19842201,
  current_block: 19832000,
  recipient: RECIPIENT,
  condition_recipient: RECIPIENT,
  amount: 500,
  max_transfer: 1000,
  proof_tx: "0x" + "a".repeat(64),
};

function makeTask(taskId, proofTx, overrides = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "test",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    input: { ...INPUT_BASE, ...overrides, proof_tx: proofTx },
  };
}

function sign(body) {
  return hmacHex(TEST_SECRET, body);
}

async function post(pathname, envelope, secret = TEST_SECRET) {
  const body = JSON.stringify(envelope);
  const headers = { "content-type": "application/json" };
  if (secret !== null) headers["x-agent-games-signature"] = sign(body);
  const res = await fetch(`${BASE_URL}${pathname}`, {
    method: "POST",
    headers,
    body,
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  const text = await res.text();
  return { status: res.status, text, sig: res.headers.get("x-agent-games-signature") };
}

function checkSignature(text, sig) {
  return sig !== null && sig === hmacHex(TEST_SECRET, text);
}

async function postTask(taskId, proofTx, overrides, pathname = "/agent") {
  const envelope = makeTask(taskId, proofTx, overrides);
  const r = await post(pathname, envelope);
  return { ...r, body: JSON.parse(r.text) };
}

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) process.exitCode = 1;
}

async function waitForHealth(timeoutMs = 30_000) {
  const t0 = Date.now();
  let attempt = 0;
  while (Date.now() - t0 < timeoutMs) {
    attempt++;
    try {
      dbg(`health attempt ${attempt}...`);
      const res = await fetch(`${BASE_URL}/health?selftest=1`, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (res.ok) return await res.json();
      dbg(`health attempt ${attempt}: HTTP ${res.status}`);
    } catch (e) {
      dbg(`health attempt ${attempt}: ${e.name} ${e.message}`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("server did not become healthy in time");
}

async function main() {
  const stateDir = mkdtempSync(path.join(tmpdir(), "robi-gk-test-"));
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: ROOT,
    env: {
      ...process.env,
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
      PORT: String(PORT),
      STATE_FILE: path.join(stateDir, "state.json"),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverLog = "";
  child.stdout.on("data", (d) => (serverLog += d.toString()));
  child.stderr.on("data", (d) => {
    serverLog += d.toString();
    dbg("server stderr:", d.toString().trim().slice(0, 300));
  });
  child.on("error", (e) => dbg("server spawn error:", e.message));
  child.on("exit", (code, signal) =>
    dbg(`server exited: code=${code} signal=${signal}`),
  );
  dbg("spawned server, pid", child.pid);

  try {
    // 1. /health: ok, HMAC configured, circuits present, self-test OK.
    // Note: health.circuits.vk is the verification-key INFO object
    // ({protocol, curve, nPublic}), not the presence boolean.
    const health = await waitForHealth();
    check(
      "GET /health ok + HMAC configured + circuits + self-test OK",
      health.ok === true &&
        health.hmacConfigured === true &&
        health.circuits.wasm === true &&
        health.circuits.zkey === true &&
        health.circuits.vk !== null &&
        health.circuits.vk.nPublic === 13 &&
        health.circuits.vkHash === GATEKEEPER_VK_HASH &&
        health.selfTest.ok === true,
      JSON.stringify(health.selfTest.detail),
    );

    // 2. Preflight, official type, correctly signed.
    {
      const envelope = {
        type: "agent-games.preflight.v1",
        agent_id: "ROBI-TRADER",
        issued_at: new Date().toISOString(),
        nonce: "test-nonce-001",
      };
      const r = await post("/agent", envelope);
      const body = JSON.parse(r.text);
      check(
        "preflight (official type) -> {ok:true, protocolVersion:v1} + valid signature",
        r.status === 200 &&
          body.ok === true &&
          body.protocolVersion === "v1" &&
          checkSignature(r.text, r.sig),
        `status=${r.status} body=${r.text.slice(0, 80)}`,
      );
    }

    // 3. Preflight, dashboard spelling ({type:"preflight", payload:{agent}}).
    {
      const envelope = {
        type: "preflight",
        taskId: "pf-1",
        timestamp: Date.now(),
        challenge: "test-challenge",
        nonce: "test-nonce-002",
        payload: { agent: "ROBI-TRADER", version: "v1" },
      };
      const r = await post("/agent", envelope);
      const body = JSON.parse(r.text);
      check(
        "preflight (dashboard spelling) -> {ok:true, protocolVersion:v1} + valid signature",
        r.status === 200 &&
          body.ok === true &&
          body.protocolVersion === "v1" &&
          checkSignature(r.text, r.sig),
        `status=${r.status} body=${r.text.slice(0, 80)}`,
      );
    }

    // 4. Bad signature -> 401.
    {
      const body = JSON.stringify({ type: "agent-games.preflight.v1" });
      const res = await fetch(`${BASE_URL}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": "00".repeat(32),
        },
        body,
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      check("bad signature -> 401", res.status === 401, `status=${res.status}`);
    }

    // 5. Missing signature -> 401.
    {
      const r = await post("/agent", { type: "agent-games.preflight.v1" }, null);
      check("missing signature -> 401", r.status === 401, `status=${r.status}`);
    }

    // 6. Valid task on /agent -> APPROVE/VALID_CONDITION + verifying proof.
    let validBodyText;
    {
      const r = await postTask(
        "e2e-valid-001",
        "0x" + "a".repeat(64),
        {},
        "/agent",
      );
      validBodyText = r.text;
      const proofOk =
        r.body.proof &&
        Array.isArray(r.body.public_signals) &&
        r.body.public_signals.length === 13 &&
        (await verifyProof(r.body.proof, r.body.public_signals));
      check(
        "valid task -> APPROVE/VALID_CONDITION + verifying Groth16 proof + valid signature",
        r.status === 200 &&
          r.body.decision === "APPROVE" &&
          r.body.reason_code === "VALID_CONDITION" &&
          proofOk === true &&
          checkSignature(r.text, r.sig),
        `status=${r.status} decision=${r.body.decision} proofOk=${proofOk}`,
      );
    }

    // 7. Same task_id replay -> byte-identical cached body.
    {
      const r = await postTask("e2e-valid-001", "0x" + "a".repeat(64), {});
      check(
        "same task_id replay -> byte-identical cached response",
        r.status === 200 && r.text === validBodyText,
        `identical=${r.text === validBodyText}`,
      );
    }

    // 8-12. Trap tasks -> correct REJECT + verifying proof + valid signature.
    const traps = [
      [
        "VK_SUBSTITUTION",
        "0x" + "b".repeat(64),
        { proof_vk: "0x" + "1".repeat(64) },
      ],
      ["THRESHOLD_MISMATCH", "0x" + "c".repeat(64), { public_balance: 999 }],
      [
        "RECIPIENT_MISMATCH",
        "0x" + "d".repeat(64),
        { recipient: "0xde4200000000000000000000000000000000beef" },
      ],
      ["AMOUNT_OVERFLOW", "0x" + "e".repeat(64), { amount: 1001 }],
      ["EXPIRED_CONDITION", "0x" + "f".repeat(64), { current_block: 19842202 }],
    ];
    for (const [reason, proofTx, overrides] of traps) {
      const r = await postTask(`e2e-trap-${reason}`, proofTx, overrides);
      const proofOk =
        r.body.proof &&
        Array.isArray(r.body.public_signals) &&
        r.body.public_signals.length === 13 &&
        (await verifyProof(r.body.proof, r.body.public_signals));
      check(
        `trap ${reason} -> REJECT/${reason} + verifying proof`,
        r.status === 200 &&
          r.body.decision === "REJECT" &&
          r.body.reason_code === reason &&
          proofOk === true &&
          checkSignature(r.text, r.sig),
        `status=${r.status} decision=${r.body.decision} proofOk=${proofOk}`,
      );
    }

    // 13. Reused proof_tx under a different task -> REJECT/PROOF_REUSED, no proof.
    {
      const r = await postTask("e2e-reused-001", "0x" + "a".repeat(64), {});
      check(
        "reused proof_tx -> REJECT/PROOF_REUSED with no proof field",
        r.status === 200 &&
          r.body.decision === "REJECT" &&
          r.body.reason_code === "PROOF_REUSED" &&
          !("proof" in r.body) &&
          checkSignature(r.text, r.sig),
        `status=${r.status} body=${r.text.slice(0, 120)}`,
      );
    }

    // 14. Malformed task (missing input) -> REJECT/INVALID_TASK.
    {
      const envelope = {
        type: "agent-games.proof-gatekeeper.v1",
        task_id: "e2e-malformed-001",
      };
      const r = await post("/agent", envelope);
      const body = JSON.parse(r.text);
      check(
        "malformed task -> REJECT/INVALID_TASK",
        r.status === 200 &&
          body.decision === "REJECT" &&
          body.reason_code === "INVALID_TASK",
        `status=${r.status} body=${r.text.slice(0, 100)}`,
      );
    }

    // 15. Unknown route -> 404.
    {
      const res = await fetch(`${BASE_URL}/nope`, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      check("unknown route -> 404", res.status === 404, `status=${res.status}`);
    }
  } finally {
    dbg("cleaning up: killing server");
    child.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 500));
    rmSync(stateDir, { recursive: true, force: true });
    if (process.exitCode === 1) {
      console.log("\n--- server log (tail) ---\n" + serverLog.slice(-3000));
    }
  }

  const passed = results.filter((r) => r.ok).length;
  console.log(`\n${passed}/${results.length} checks passed`);
  // Force exit: do not let stray handles (undici keep-alive, child pipes)
  // mask the result by holding the event loop open.
  process.exit(passed === results.length ? 0 : 1);
}

main().catch((e) => {
  console.error("e2e harness error:", e);
  process.exit(1);
});
