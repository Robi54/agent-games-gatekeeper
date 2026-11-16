// Disk-backed state for the gatekeeper: the proof-reuse seen-set and the
// idempotency cache. Persisted so a restart cannot let a reused proof
// through and so a retried task gets the identical response.
//
// The file holds ONLY proof_tx hashes and task IDs plus cached response
// bodies — no secrets, no HMAC values, no salts.
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

const EMPTY = { seenProofTx: [], cachedResponses: {} };

export class StateStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.data = { ...EMPTY, seenProofTx: [], cachedResponses: {} };
    if (existsSync(filePath)) {
      try {
        const parsed = JSON.parse(readFileSync(filePath, "utf8"));
        if (Array.isArray(parsed.seenProofTx)) {
          this.data.seenProofTx = parsed.seenProofTx;
        }
        if (
          parsed.cachedResponses &&
          typeof parsed.cachedResponses === "object"
        ) {
          this.data.cachedResponses = parsed.cachedResponses;
        }
      } catch {
        // Corrupt state file: start empty rather than crash the server.
        this.data = { ...EMPTY, seenProofTx: [], cachedResponses: {} };
      }
    }
    this.seen = new Set(this.data.seenProofTx);
  }

  save() {
    this.data.seenProofTx = [...this.seen];
    const tmp = `${this.filePath}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.data));
    renameSync(tmp, this.filePath);
  }

  markProofTxSeen(proofTx) {
    if (!this.seen.has(proofTx)) {
      this.seen.add(proofTx);
      this.save();
    }
  }

  getCachedResponse(taskId) {
    const entry = this.data.cachedResponses[taskId];
    return entry ? { body: entry } : null;
  }

  cacheResponse(taskId, body) {
    this.data.cachedResponses[taskId] = body;
    this.save();
  }

  stats() {
    return {
      seenProofTx: this.seen.size,
      cachedResponses: Object.keys(this.data.cachedResponses).length,
      file: this.filePath,
    };
  }
}
