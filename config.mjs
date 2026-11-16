// Shared constants and environment config for the ROBI-TRADER gatekeeper.
//
// No secrets live in this file. The platform HMAC secret comes ONLY from the
// AGENT_GAMES_HMAC_SECRET environment variable (dashboard -> Rotate Secret).
// It is never logged, never written to disk, never committed.
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const AGENT_ID = "ROBI-TRADER";
export const PROTOCOL_VERSION = "v1";

// Envelope types the platform sends. The practice-validated type is
// "agent-games.proof-gatekeeper.v1" (confirmed by a community build that got
// a practice proof VERIFIED on 2026-11-16). The dashboard's own description
// used the shorter spellings "preflight" / "proof-gatekeeper", so the server
// accepts both spellings for robustness — answering either preflight shape
// with { ok: true, protocolVersion: "v1" } is the correct behaviour.
export const TASK_TYPES = [
  "agent-games.proof-gatekeeper.v1",
  "proof-gatekeeper",
];
export const PREFLIGHT_TYPES = [
  "agent-games.preflight.v1",
  "preflight",
];

// bn128 scalar field prime — 256-bit hashes are reduced mod this prime
// before entering the circuit.
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Gatekeeper circuit verification-key hash, registered on zkVerify mainnet.
// Source: https://agentgames.zkverify.io/api/circuit-info (fetched 2026-11-16).
// NOTE: this is the hash of the *gatekeeper circuit's own* verification key
// (used when submitting OUR decision proof to Kurier/zkVerify). It is NOT
// compared against the task's registered_vk / proof_vk fields — those belong
// to the payment condition's proof; the circuit only checks the two are equal.
export const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export const CIRCUIT_DIR =
  process.env.CIRCUIT_DIR || path.join(__dirname, "circuits");
export const WASM_PATH = path.join(CIRCUIT_DIR, "gatekeeper.wasm");
export const ZKEY_PATH = path.join(CIRCUIT_DIR, "gatekeeper_final.zkey");
export const VK_PATH = path.join(CIRCUIT_DIR, "verification_key.json");

export const PORT = Number(process.env.PORT || 3000);
export const STATE_FILE =
  process.env.STATE_FILE || path.join(__dirname, "state.json");

// Hard internal budget for proof generation. The platform allows 60 s per
// response; proof generation takes ~0.3-0.9 s locally. If it ever exceeds
// this budget we answer the deterministic decision WITHOUT a proof instead
// of timing out (a correct decision without proof still scores on traps).
export const PROOF_TIMEOUT_MS = 45_000;

export function hmacSecret() {
  const s = (process.env.AGENT_GAMES_HMAC_SECRET || "").trim();
  return s.length > 0 ? s : null;
}

export function circuitsPresent() {
  return {
    wasm: existsSync(WASM_PATH),
    zkey: existsSync(ZKEY_PATH),
    vk: existsSync(VK_PATH),
  };
}
