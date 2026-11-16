// Proof Gatekeeper HTTP endpoint for agent ROBI-TRADER — plain Node.js http,
// no framework.
//
// Routes:
//   POST /agent       (primary; /gatekeeper is accepted as an alias)
//     - Verifies x-agent-games-signature (HMAC-SHA256 over the RAW body)
//       BEFORE parsing. Mismatch -> 401, no processing.
//     - type "agent-games.preflight.v1" (or "preflight") ->
//       { ok: true, protocolVersion: "v1" }, signed.
//     - type "agent-games.proof-gatekeeper.v1" -> deterministic decision +
//       local Groth16 proof, signed. 60 s platform deadline; the internal
//       proof budget is 45 s, after which we answer the decision WITHOUT a
//       proof rather than timing out.
//     - Every response carries x-agent-games-signature over the raw body.
//   GET /health
//     - Readiness: HMAC configured?, circuit files present?, verification
//       key (nPublic), state sizes, last startup self-test result.
//     - GET /health?selftest=1 re-runs the self-test on demand.
//
// This server NEVER signs transactions, NEVER spends anything, and NEVER
// stores a private key or seed. The only secret it holds is the platform
// HMAC secret from AGENT_GAMES_HMAC_SECRET (never logged).
import http from "node:http";
import {
  CIRCUIT_DIR,
  GATEKEEPER_VK_HASH,
  PORT,
  PREFLIGHT_TYPES,
  PROTOCOL_VERSION,
  STATE_FILE,
  TASK_TYPES,
  circuitsPresent,
  hmacSecret,
} from "./config.mjs";
import { hmacHex, verifySignature } from "./hmac.mjs";
import { REASON, buildCircuitInput, decide, parseTask } from "./decision.mjs";
import { generateProof, loadVerificationKey, verifyProof } from "./proof.mjs";
import { runSelfTest } from "./selftest.mjs";
import { StateStore } from "./state.mjs";

const state = new StateStore(STATE_FILE);
const selfTest = { ranAt: null, ok: null, detail: null, proofMs: null };

function logLine(event, fields = {}) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    event,
    ...fields,
  });
  console.log(line);
}

function json(res, status, bodyObj, secret) {
  const body = JSON.stringify(bodyObj);
  const headers = { "content-type": "application/json" };
  if (secret) headers["x-agent-games-signature"] = hmacHex(secret, body);
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) reject(new Error("body too large"));
      else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function handleTask(req, res, secret) {
  const t0 = Date.now();
  let raw;
  try {
    raw = await readRawBody(req);
  } catch (e) {
    return json(res, 400, { error: "bad request body" }, null);
  }

  // 1. HMAC first, BEFORE parsing. Fail closed.
  const sig = req.headers["x-agent-games-signature"];
  if (!secret) {
    logLine("not-configured", { ms: Date.now() - t0 });
    return json(
      res,
      503,
      { error: "agent not configured (HMAC secret missing)" },
      null,
    );
  }
  if (!verifySignature(secret, raw, sig)) {
    logLine("bad-signature", { ms: Date.now() - t0 });
    return json(res, 401, { error: "bad signature" }, null);
  }

  let envelope;
  try {
    envelope = JSON.parse(raw.toString("utf8"));
  } catch {
    return json(res, 400, { error: "invalid JSON" }, null);
  }

  // 2. Preflight handshake (same endpoint, distinguished by type).
  if (envelope && PREFLIGHT_TYPES.includes(envelope.type)) {
    logLine("preflight", {
      agent: envelope.agent_id ?? envelope.payload?.agent ?? null,
      nonce: String(envelope.nonce ?? "?").slice(0, 24),
      ms: Date.now() - t0,
    });
    return json(
      res,
      200,
      { ok: true, protocolVersion: PROTOCOL_VERSION },
      secret,
    );
  }

  if (!envelope || !TASK_TYPES.includes(envelope.type)) {
    return json(res, 400, { error: `unexpected type: ${String(envelope?.type)}` }, null);
  }

  // 3. Parse + decide deterministically.
  let task;
  try {
    task = parseTask(envelope);
  } catch (e) {
    logLine("invalid-task", { error: e.message, ms: Date.now() - t0 });
    return json(
      res,
      200,
      { decision: "REJECT", reason_code: REASON.INVALID_TASK },
      secret,
    );
  }

  // 4. Idempotency: same task_id -> same response (platform retries).
  const cached = state.getCachedResponse(task.taskId);
  if (cached) {
    logLine("idempotent-replay", {
      taskId: task.taskId,
      decision: JSON.parse(cached.body).decision,
      ms: Date.now() - t0,
    });
    const headers = {
      "content-type": "application/json",
      "x-agent-games-signature": hmacHex(secret, cached.body),
    };
    res.writeHead(200, headers);
    return res.end(cached.body);
  }

  const { decision, reasonCode, needsProof } = decide(task, state.seen);
  const response = {
    decision,
    reason_code: reasonCode,
    proof_tx: task.proofTx,
  };

  // 5. Prove the decision locally (except PROOF_REUSED: no proof to submit).
  if (needsProof) {
    try {
      const input = buildCircuitInput(task, decision);
      const { proof, publicSignals, proofMs } = await generateProof(input);
      response.proof = proof;
      response.public_signals = publicSignals;
      logLine("decision", {
        taskId: task.taskId,
        decision,
        reasonCode,
        proofMs,
        ms: Date.now() - t0,
      });
    } catch (e) {
      // Fail closed on the DECISION, not on transport: answer the decision
      // without a proof (costs -2) rather than timing out (also -2, but a
      // correct REJECT without proof still scores on trap tasks).
      logLine("proof-failed", {
        taskId: task.taskId,
        decision,
        reasonCode,
        error: e.message,
        ms: Date.now() - t0,
      });
    }
  } else {
    logLine("decision-no-proof", {
      taskId: task.taskId,
      decision,
      reasonCode,
      ms: Date.now() - t0,
    });
  }

  // 6. Record the reference as seen + cache the response, then answer signed.
  state.markProofTxSeen(task.proofTx);
  const body = JSON.stringify(response);
  state.cacheResponse(task.taskId, body);
  const headers = {
    "content-type": "application/json",
    "x-agent-games-signature": hmacHex(secret, body),
  };
  res.writeHead(200, headers);
  res.end(body);
}

function healthPayload() {
  const present = circuitsPresent();
  let vkInfo = null;
  try {
    const vk = loadVerificationKey();
    vkInfo = { protocol: vk.protocol, curve: vk.curve, nPublic: vk.nPublic };
  } catch (e) {
    vkInfo = { error: String(e.message || e) };
  }
  return {
    ok:
      Boolean(hmacSecret()) &&
      present.wasm &&
      present.zkey &&
      present.vk &&
      selfTest.ok !== false,
    protocolVersion: PROTOCOL_VERSION,
    hmacConfigured: Boolean(hmacSecret()),
    circuits: { ...present, dir: CIRCUIT_DIR, vkHash: GATEKEEPER_VK_HASH, vk: vkInfo },
    state: state.stats(),
    selfTest,
  };
}

async function handleHealth(req, res) {
  const url = new URL(req.url, "http://localhost");
  if (url.searchParams.get("selftest") === "1") {
    const result = await runSelfTest();
    Object.assign(selfTest, result);
    return json(res, 200, healthPayload(), null);
  }
  return json(res, 200, healthPayload(), null);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (req.method === "GET" && url.pathname === "/health") {
    return handleHealth(req, res);
  }
  if (
    req.method === "POST" &&
    (url.pathname === "/agent" || url.pathname === "/gatekeeper")
  ) {
    return handleTask(req, res, hmacSecret()).catch((e) => {
      logLine("handler-error", { error: e.message });
      try {
        json(res, 500, { error: "internal error" }, null);
      } catch {
        /* socket already gone */
      }
    });
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
});

server.requestTimeout = 55_000;
server.headersTimeout = 60_000;

// Self-test BEFORE accepting traffic, so /health is truthful from the first
// request. A failed self-test does not stop the server (so /health can
// report it), but it is logged loudly.
const startupTest = await runSelfTest();
Object.assign(selfTest, startupTest);
logLine("startup-selftest", {
  ok: startupTest.ok,
  detail: startupTest.detail,
  proofMs: startupTest.proofMs,
});
if (!startupTest.ok) {
  console.error("[gatekeeper] WARNING: self-test failed — endpoint is NOT competition-ready");
}

server.listen(PORT, () => {
  logLine("listening", {
    port: PORT,
    routes: "POST /agent, POST /gatekeeper, GET /health",
    hmacConfigured: Boolean(hmacSecret()),
    circuits: circuitsPresent(),
  });
});

export { server };
