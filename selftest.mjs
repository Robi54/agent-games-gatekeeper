// Startup self-test for the ROBI-TRADER gatekeeper.
//
// Runs the 12-case decision + circuit matrix through the real decision and
// proving code, plus a Poseidon commitment check (public[0] must equal
// Poseidon(salt, taskId) — the formula the platform re-derives).
// No secret needed, no network, no spending. Exit 0 when all cases pass.
//
// Sample values are the official event-page example: minimum 1000, balance
// 1460, expiry 19842201, current 19832000, amount 500, cap 1000, recipient
// == condition recipient, vk hashes equal.
import { buildPoseidon } from "circomlibjs";
import { GATEKEEPER_VK_HASH } from "./config.mjs";
import { REASON, buildCircuitInput, decide } from "./decision.mjs";
import { generateProof, loadVerificationKey, verifyProof } from "./proof.mjs";

const BASE = {
  minimum: 1000n,
  publicBalance: 1460n,
  expiryBlock: 19842201n,
  currentBlock: 19832000n,
  recipient: "0xde42000000000000000000000000000000009f01",
  conditionRecipient: "0xde42000000000000000000000000000000009f01",
  amount: 500n,
  maxTransfer: 1000n,
  registeredVk: GATEKEEPER_VK_HASH,
  proofVk: GATEKEEPER_VK_HASH,
};

function taskWith(overrides, proofTx) {
  return {
    taskId: "selftest-gk",
    mode: "practice",
    ...BASE,
    ...overrides,
    proofTx,
  };
}

const SCENARIOS = [
  {
    name: "VALID_CONDITION",
    overrides: {},
    expect: { decision: "APPROVE", reasonCode: REASON.VALID },
  },
  {
    name: "VK_SUBSTITUTION",
    overrides: {
      proofVk: "0x1111111111111111111111111111111111111111111111111111111111111111",
    },
    expect: { decision: "REJECT", reasonCode: REASON.VK_SUBSTITUTION },
  },
  {
    name: "THRESHOLD_MISMATCH",
    overrides: { publicBalance: 999n },
    expect: { decision: "REJECT", reasonCode: REASON.THRESHOLD_MISMATCH },
  },
  {
    name: "RECIPIENT_MISMATCH",
    overrides: {
      recipient: "0xde4200000000000000000000000000000000beef",
    },
    expect: { decision: "REJECT", reasonCode: REASON.RECIPIENT_MISMATCH },
  },
  {
    name: "AMOUNT_OVERFLOW",
    overrides: { amount: 1001n },
    expect: { decision: "REJECT", reasonCode: REASON.AMOUNT_OVERFLOW },
  },
  {
    name: "EXPIRED_CONDITION",
    overrides: { currentBlock: 19842202n },
    expect: { decision: "REJECT", reasonCode: REASON.EXPIRED_CONDITION },
  },
];

function opposite(decision) {
  return decision === "APPROVE" ? "REJECT" : "APPROVE";
}

export async function runSelfTest() {
  const result = { ranAt: new Date().toISOString(), ok: false, detail: null, proofMs: null };
  const t0 = Date.now();
  try {
    // 0. Verification key sanity: Groth16 / bn128 / 13 public signals.
    const vk = loadVerificationKey();
    if (vk.protocol !== "groth16" || vk.curve !== "bn128" || vk.nPublic !== 13) {
      throw new Error(
        `unexpected verification key: ${vk.protocol}/${vk.curve}/nPublic=${vk.nPublic}`,
      );
    }

    let proofMs = 0;
    let cases = 0;
    for (let i = 0; i < SCENARIOS.length; i++) {
      const sc = SCENARIOS[i];
      const proofTx = `0x${(i + 1).toString(16).padStart(64, "0")}`;
      const task = taskWith(sc.overrides, proofTx);

      // 1. The decision module must return the expected decision/reason.
      const d = decide(task, new Set());
      if (d.decision !== sc.expect.decision || d.reasonCode !== sc.expect.reasonCode) {
        throw new Error(
          `${sc.name}: decide() gave ${d.decision}/${d.reasonCode}, expected ${sc.expect.decision}/${sc.expect.reasonCode}`,
        );
      }
      cases++;

      // 2. A proof for the CORRECT decision must generate and verify.
      const input = buildCircuitInput(task, d.decision);
      const { proof, publicSignals, proofMs: ms } = await generateProof(input);
      proofMs = Math.max(proofMs, ms);
      if (publicSignals.length !== 13) {
        throw new Error(`${sc.name}: expected 13 public signals, got ${publicSignals.length}`);
      }
      if (!(await verifyProof(proof, publicSignals))) {
        throw new Error(`${sc.name}: generated proof did not verify`);
      }
      cases++;

      // 3. A proof for the OPPOSITE decision must be REFUSED by the circuit
      //    (the circuit is the referee: it enforces the same logic).
      const wrongInput = buildCircuitInput(task, opposite(d.decision));
      let refused = false;
      try {
        await generateProof(wrongInput, 30_000);
      } catch {
        refused = true;
      }
      if (!refused) {
        throw new Error(`${sc.name}: circuit generated a proof for the WRONG decision`);
      }
      cases++;
    }

    // 4. Commitment formula: public[0] == Poseidon(salt, taskId).
    const poseidon = await buildPoseidon();
    const task = taskWith({}, "0x" + "f".repeat(64));
    const saltHex = "00112233445566778899aabbccddeeff";
    const input = buildCircuitInput(task, "APPROVE", saltHex);
    const { publicSignals } = await generateProof(input);
    const saltBig = BigInt("0x" + saltHex);
    const taskIdBig = BigInt(input.taskId);
    const commitment = poseidon.F.toObject(poseidon([saltBig, taskIdBig]));
    if (commitment !== BigInt(publicSignals[0])) {
      throw new Error("commitment mismatch: public[0] != Poseidon(salt, taskId)");
    }
    cases++;

    result.ok = true;
    result.proofMs = proofMs;
    result.detail = `${cases} cases passed (6 scenarios x decide/prove/refuse + commitment check), max proof ${proofMs}ms, total ${Date.now() - t0}ms`;
  } catch (e) {
    result.ok = false;
    result.detail = String(e.message || e);
  }
  return result;
}

// Runnable directly: `node selftest.mjs`
if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSelfTest();
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.ok ? 0 : 1);
}
