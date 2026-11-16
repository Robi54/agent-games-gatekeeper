# ROBI-TRADER — Proof Gatekeeper endpoint (zkVerify Agent Games Season 01)

Public-agent endpoint service for **ROBI-TRADER**, the agent registered for
the Proof Gatekeeper track at
https://agentgames.zkverify.io/dashboard/agents (owner @robi54, repo
https://github.com/Robi54/paper-trading-bot).

It receives the platform's signed task envelopes, decides APPROVE / REJECT
by a fixed deterministic checklist (never an LLM judgement), generates a
Groth16 proof of that decision locally with snarkjs + the official
gatekeeper circuit, and returns the signed protocol-v1 response — all
inside the platform's 60-second deadline. No private keys, no transactions,
no spending: this server only judges and proves.

**Status (2026-11-16): built + verified locally. NOT deployed.** The deploy
step needs the account holder (see [Deployment](#deployment)).

## Run locally

```bash
cd ~/workspace/agent-games-endpoint
npm install            # snarkjs 0.7.6 + circomlibjs 0.1.7 (Node >= 20)
cp .env.example .env   # then fill AGENT_GAMES_HMAC_SECRET (see below)
npm run selftest       # 19-case decision + circuit matrix, no secret needed
npm test               # 15-check live-server test (fake test secret)
npm start              # listens on $PORT (default 3000)
curl localhost:3000/health
```

## Environment variables

| Variable | Required | Notes |
| --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | yes | Platform HMAC secret, from the Agent Games dashboard (My Agents → ROBI-TRADER → **Rotate Secret**). Shown exactly once — **the owner enters it as an env var at deploy time. Never commit it, never paste it into any chat, never put it in any file.** Without it the server refuses to answer (503) and `/health` reports `hmacConfigured: false`. |
| `PORT` | no | Default 3000. Hosting platforms inject their own. |
| `CIRCUIT_DIR` | no | Default `./circuits` (gatekeeper.wasm, gatekeeper_final.zkey, verification_key.json). |
| `STATE_FILE` | no | Default `./state.json` (proof-reuse seen-set + idempotency cache). |

## Files

```
agent-games-endpoint/
  server.mjs            HTTP server (POST /agent, POST /gatekeeper alias, GET /health)
  decision.mjs          deterministic checks + circuit input builder
  proof.mjs             snarkjs fullProve/verify wrapper (45 s budget)
  hmac.mjs              HMAC-SHA256 sign/verify (raw body, lowercase hex)
  state.mjs             proof-reuse seen-set + idempotency cache (disk JSON)
  config.mjs            constants (vk hash, field prime, paths, env)
  selftest.mjs          19-case decision + circuit matrix (npm run selftest)
  test/e2e-test.mjs     15-check live-server test (npm test, fake test secret)
  circuits/
    gatekeeper.wasm             official circuit (1,755,820 bytes, sha256 be00aefe…92764f)
    gatekeeper_final.zkey       official proving key (309,750 bytes, sha256 adfe95a4…01af80d)
    verification_key.json       exported from the zkey with snarkjs 0.7.6
                                (Groth16 / bn128 / nPublic 13, sha256 6ce4899b…28221)
  railway.json          Railway deploy config (Nixpacks, start + healthcheck)
  .env.example          env template (no real values)
  .gitignore            node_modules, .env, state.json, logs
```

## Protocol summary

Sources: https://agentgames.zkverify.io/build, `/api/circuit-info`
(fetched 2026-11-16), the event/rules pages, and a community build that got
a practice proof VERIFIED on the live platform on 2026-11-16 (see
[References](#references)).

### Inbound

- `POST` JSON to the registered endpoint (full handler path, e.g.
  `https://<host>/agent`). Header `x-agent-games-signature` = HMAC-SHA256
  (lowercase hex) over the **RAW** body, verified **BEFORE** parsing.
  Bad/missing signature → `401`, nothing processed. No secret configured
  → `503`. 60 s hard deadline, HTTPS only, public registered endpoint.
  Fail closed everywhere.
- Preflight: `{type: "agent-games.preflight.v1", agent_id, issued_at,
  nonce}` → answer `{ok: true, protocolVersion: "v1"}`, signed. (The
  dashboard's own description used the shorter spelling
  `{type: "preflight", ..., payload: {agent, version}}` — this server
  accepts **both** spellings; see [Open points](#open-points).)
- Task: `{type: "agent-games.proof-gatekeeper.v1", task_id, mode,
  issued_at, deadline_at, input: {registered_vk, proof_vk, minimum,
  public_balance, expiry_block, current_block, recipient,
  condition_recipient, amount, max_transfer, proof_tx}}`.

### Response

`{decision, reason_code, proof_tx, proof, public_signals}`, signed with
the same HMAC over the raw response body. `proof` is the raw snarkjs
Groth16 proof; `public_signals` are 13 decimal strings in
output-then-public order. `PROOF_REUSED` answers carry **no** proof (the
rules exclude them from the reliability bonus).

### Decision checklist (in order)

1. envelope malformed → REJECT / `INVALID_TASK` (no proof)
2. task_id seen before → return the cached response (idempotency; the
   platform retries after network failures)
3. proof_tx seen under another task_id → REJECT / `PROOF_REUSED` (no proof)
4. incoming proof explicitly marked invalid / not finalized (only if the
   platform attaches a verification-status field) → REJECT / `INVALID_PROOF`
5. proof_vk != registered_vk → REJECT / `VK_SUBSTITUTION`
6. public_balance < minimum → REJECT / `THRESHOLD_MISMATCH`
7. recipient != condition_recipient → REJECT / `RECIPIENT_MISMATCH`
8. amount > max_transfer → REJECT / `AMOUNT_OVERFLOW`
9. current_block > expiry_block → REJECT / `EXPIRED_CONDITION`
10. otherwise → APPROVE / `VALID_CONDITION`

The gatekeeper circuit enforces the SAME logic: it refuses to generate a
witness for a decision that contradicts the inputs (assertion in template
`GatekeeperEvaluation_79`). A proof can only ever be produced for the
decision this module computes — the circuit is the referee. If proof
generation fails on an APPROVE, the server fails closed to the decision
without a proof rather than timing out.

### Circuit facts (verified locally)

- Groth16 / bn128, Circom 2.x, **nPublic = 13**, witness size 647.
- Registered vk hash (zkVerify mainnet, from `/api/circuit-info`):
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- 13 circuit inputs (found by probing the compiled wasm; the docs do not
  publish signal names): `taskId, minimum, publicBalance, expiryBlock,
  currentBlock, recipient, conditionRecipient, amount, maxTransfer,
  registeredVkHash, proofVkHash, salt, decision` (1 = approve, 0 = reject).
- Public signals (13, output-then-public order): `[commitment,
  registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
  currentBlock, recipient, conditionRecipient, amount, maxTransfer,
  decision, taskId]`, where `commitment = Poseidon(salt, taskId)` —
  confirmed locally (see self-test).
- Encodings: 256-bit hashes reduced mod the bn128 field prime (the
  registered vk hash itself exceeds the prime, so the reduced value
  `4836144126773920907502496244340012141761656471453348073975163706578152814510`
  appears in the public signals); addresses as `BigInt(hex)`; task_id
  string as `BigInt` of its UTF-8 bytes; salt fresh random 128-bit per
  proof (private, never logged, never returned).
- Proof generation: ~270–980 ms locally — far inside the 60 s deadline.

### Why there is no zkVerifyJS dependency

The task envelope carries **no proof bytes** — only the incoming proof's
vk hash (`proof_vk`) and its reference (`proof_tx`). The agent therefore
cannot re-run the Groth16 verification itself; what it can check is the vk
equality, the reference reuse, and (if the platform attaches one) the
explicit verification-status field. The platform re-verifies OUR decision
proof independently, and submitting that proof on-chain (Kurier /
zkVerifyJS) is optional — the response schema does not require it. If the
owner later gets a Kurier API key, proofs can additionally be submitted
(`proofType: groth16, vkRegistered: true`, vk =
`0x6b79c6…d77b0`) and polled to Finalized, but it is not needed to score.

### Steal the VFY — out of scope (phase 2)

Not implemented. It needs a strategy commitment hash + Groth16/BN128
Circom policy proofs per turn (vfy-policy circuit, vk hash
`0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`,
artifacts at `/circuits/vfy-policy.wasm` and
`/circuits/vfy-policy_final.zkey`), a committed policy the agent's
strategy is bound to, and per-turn public-inputs hashing. The same
endpoint/harness pattern applies, but the policy decision and the ZK
circuit work are a separate build.

## Test results

All tests run locally on 2026-11-16, Node v22.23.5, no secrets, no deploy,
no network calls to zkVerify mainnet. The only secret-like string in the
tree is the clearly labelled fake test secret inside `test/e2e-test.mjs`.

### Self-test — `node selftest.mjs` → 19/19 pass

```
$ node selftest.mjs
{
  "ranAt": "2026-11-16T07:42:56.684Z",
  "ok": true,
  "detail": "19 cases passed (6 scenarios x decide/prove/refuse + commitment check), max proof 868ms, total 3682ms",
  "proofMs": 868
}
```

19 cases = 6 scenarios (VALID, VK_SUBSTITUTION, THRESHOLD_MISMATCH,
RECIPIENT_MISMATCH, AMOUNT_OVERFLOW, EXPIRED_CONDITION) ×
(decide-correct + proof-generates-and-verifies + proof-for-the-OPPOSITE-decision-is-refused-by-the-circuit)
+ the Poseidon commitment check (`public[0] == Poseidon(salt, taskId)`).
The `Error in template GatekeeperEvaluation_79 line: 102` lines on stderr
are the EXPECTED circuit refusals for wrong decisions, not failures.

### End-to-end — `node test/e2e-test.mjs` → 15/15 pass (14.4 s)

```
PASS  GET /health ok + HMAC configured + circuits + self-test OK
PASS  preflight (official type) -> {ok:true, protocolVersion:v1} + valid signature
PASS  preflight (dashboard spelling) -> {ok:true, protocolVersion:v1} + valid signature
PASS  bad signature -> 401
PASS  missing signature -> 401
PASS  valid task -> APPROVE/VALID_CONDITION + verifying Groth16 proof + valid signature
PASS  same task_id replay -> byte-identical cached response
PASS  trap VK_SUBSTITUTION -> REJECT/VK_SUBSTITUTION + verifying proof
PASS  trap THRESHOLD_MISMATCH -> REJECT/THRESHOLD_MISMATCH + verifying proof
PASS  trap RECIPIENT_MISMATCH -> REJECT/RECIPIENT_MISMATCH + verifying proof
PASS  trap AMOUNT_OVERFLOW -> REJECT/AMOUNT_OVERFLOW + verifying proof
PASS  trap EXPIRED_CONDITION -> REJECT/EXPIRED_CONDITION + verifying proof
PASS  reused proof_tx -> REJECT/PROOF_REUSED with no proof field
PASS  malformed task -> REJECT/INVALID_TASK
PASS  unknown route -> 404

15/15 checks passed
```

The real server is spawned with the fake test secret; every response
signature is re-verified independently with Node `crypto`; every proof is
re-verified with snarkjs `groth16.verify`. A valid task answers end-to-end
in ~330 ms (proof ~300 ms) against the 60 s deadline.

### Harness notes (what broke, and the fix)

- The first e2e runs hung: `fetch()` without a timeout can wait forever
  when the server is mid-startup, and the old `waitForHealth` only checked
  its 30 s deadline *between* attempts. Fixed: every fetch now has
  `AbortSignal.timeout(8000)`, the harness logs progress to stderr, and it
  calls `process.exit()` with the result instead of relying on the event
  loop to drain.
- One test assertion was wrong (it expected `health.circuits.vk` to be a
  boolean; the payload carries the vk *info object*). Fixed to assert
  `nPublic === 13` and the vk hash.

## Deployment

The service needs a **public HTTPS URL** the platform can POST to, always
on during rounds (a sleeping host costs tasks — each missed task is a
forfeit). Options evaluated 2026-11-16 (prices are Nov-2026 snapshots from
the vendors' pricing pages / reviews; re-check before paying):

### Recommended: Railway (free plan, no card to start)

- **What it is:** usage-based PaaS. Connect a GitHub repo → Nixpacks
  auto-detects Node, builds, runs. No Dockerfile needed
  (`railway.json` in this repo sets the builder + start command +
  healthcheck). Services do **not** sleep.
- **Cost:** new accounts get a **$5 one-time trial credit (30 days, no
  credit card)**; after that a Free plan gives **$1/month credit in
  perpetuity, no card**. A minimal always-on service is estimated at
  ~$0.80–$5/month depending on the source (memory is the main cost:
  ~$10/GB-month; this service uses ~100–200 MB). The $5 trial covers
  the remaining 5 days of the competition comfortably; worst case the
  owner adds the $5/month Hobby plan (includes $5 usage). Egress
  $0.05/GB — negligible here (a few KB per task).
- **Proven for this exact workload:** another entrant's gatekeeper is live
  on Railway (`gatekeeper-production-96ab4a9e.up.railway.app/gatekeeper`)
  and got a practice proof **VERIFIED** by the platform on 2026-11-16.
- **What the owner must provide / do:**
  1. A Railway account — sign up at railway.com with GitHub (Robi's
     GitHub is **Robi54**; no card needed for the trial).
  2. This code in a GitHub repo — push this folder to a repo on Robi54
     (or give the folder to the owner to push; pushing needs his GitHub
     login, which only he has).
  3. In Railway: New Project → Deploy from GitHub repo → select the
     repo. Railway auto-detects Node and deploys.
  4. In Railway → Variables, set `AGENT_GAMES_HMAC_SECRET` to the
     platform secret (from the dashboard → Rotate Secret; **he types it
     himself** — it must never be pasted into any chat).
  5. Confirm `GET https://<app>.up.railway.app/health` returns
     `ok: true`, `hmacConfigured: true`, `selfTest.ok: true`.
  6. On the Agent Games dashboard (My Agents → ROBI-TRADER → Edit),
     set the endpoint to the full handler path
     `https://<app>.up.railway.app/agent`, save (saving runs a signed
     preflight), and confirm the agent flips to healthy.
  7. Run at least **one practice task** (dashboard Practice Mode) and
     confirm the platform accepts the proof — this is the step that
     confirms the task-id encoding and signature format for real.
- **Caveats:** Railway's free tier has had reliability rough patches in
  2025–2026 (per reviews). `state.json` lives on the service's
  ephemeral filesystem — a redeploy/restart resets the seen-set and the
  idempotency cache (decisions are deterministic, so a retried task
  re-decides identically; the residual risk is a reused proof_tx slipping
  through after a restart). Optionally attach a Railway volume (free tier
  includes 0.5 GB) mounted where `STATE_FILE` points.

### Fly.io — not recommended (no free tier)

No free tier for new organizations. New accounts get a $1 trial credit
for 7 days, no card — but trial Machines stop after 5 minutes of running
per the trial docs, and a card is required once the trial ends. Smallest
always-on machine (shared-cpu-1x, 256 MB) ≈ $2.19/month; invoices under
$5 are waived. Needs `flyctl` + account + Dockerfile/fly.toml. The
platform's own example endpoint placeholder is `my-agent.fly.dev/agent`,
but the trial limits make it a poor fit for a 5-day competition window.
Only pick this if Railway fails and the owner is willing to add a card.

### Render — free tier unsuitable (sleeps)

Free web service ($0, 512 MB / 0.1 CPU, 750 hrs/month) **spins down
after 15 minutes without traffic**; cold start takes 30–60 s — that eats
the whole 60 s task deadline, so tasks arriving after idle would time
out. External keep-alive pingers are rate-limited/blocked by Render.
Paid Starter ($7/month) is always-on and would work, but it costs money
and needs a card. Only pick the paid tier as a fallback.

### Vercel — not recommended (serverless)

Hobby ($0) is serverless with cold starts and a 10 s function limit;
Pro is $20/month. A cold start inside the 60 s window is survivable,
but an always-on service is a much better fit than serverless for an
agent that must answer at any moment. Only as a last resort.

### Tunnels from this VM — not viable

This VM has no public IP, and its egress proxy blocks the free
no-account tunnels: trycloudflare → 403, localtunnel unreachable,
bore.pub unreachable (measured from this VM on 2026-11-15). ngrok needs
an account + authtoken and a process running 24/7 on this VM — but this
VM restarts and kills background processes (the paper-trading bot has
died 4 times today alone for exactly that reason). A Cloudflare named
tunnel needs a Cloudflare account + a domain. Do not rely on a tunnel.

### What the owner must provide (summary)

- A Railway account (GitHub sign-in, no card for the trial).
- Pushing this code to a GitHub repo under Robi54 (his login).
- Typing the platform HMAC secret into Railway's Variables himself.
- Setting the endpoint URL on the Agent Games dashboard and running
  preflight + one practice task.
- Nothing else: no card, no domain, no server to maintain. The agent
  (Muse) cannot do any of these four steps — all four need the owner's
  own logins.

## Is Gatekeeper R5 (17 Nov 17:30 WIB) achievable?

**Yes — if the deploy happens tonight (16 Nov).** Honest assessment:

- **Now:** 16 Nov ~15:00 WIB. R5 opens 17 Nov 17:30 WIB — about 26
  hours away. R4 opens today 17:30 WIB — **not achievable**: the
  Railway account + GitHub push + secret entry + deploy + preflight +
  practice task cannot responsibly be rushed in ~2.5 hours, and the
  practice task is the one step that can still reveal a protocol
  mismatch (task-id encoding, signature format) that would need a fix
  and re-deploy.
- **What remains:** deploy (Railway, ~30–60 min elapsed with the owner
  clicking), endpoint registration + preflight (~10 min), ≥1 practice
  task (~10 min). All of it is routine **if** the owner is responsive
  tonight. The code itself is proven locally end-to-end (15/15).
- **Risks:** (1) Railway signup/GitHub connect friction (owner's
  logins, 2FA, etc.); (2) the practice task is the first contact with
  the real platform — if it rejects the proof, the first suspects are
  the task-id string→field encoding and the signature format, both
  flagged as assumptions in this README; (3) Railway free-tier
  reliability; (4) the agent's `state.json` resetting on redeploy
  (see above).
- **If R5 is missed:** R6 (18 Nov), R7 (19 Nov), R8 (20 Nov) remain —
  the competition closes 21 Nov 22:00 UTC, results 22–30 Nov. The 3
  content entries (2 Creator Track + 1 Wildcard) are unaffected by any
  of this and stay pending review regardless.

## Open points (verify in practice mode, not locally testable)

1. **Signature encoding:** lowercase hex HMAC-SHA256 is the standard
   convention, but the docs never spell it out. Preflight confirms it.
2. **taskId encoding:** the task-id string is hashed into a field element
   as its UTF-8 bytes. The commitment formula
   `public[0] = Poseidon(salt, taskId)` was confirmed locally with this
   encoding. If the platform rejects a practice proof, revisit this first.
3. **Envelope spellings:** the practice-validated types are
   `agent-games.preflight.v1` / `agent-games.proof-gatekeeper.v1`; the
   dashboard's own description used the shorter `preflight` /
   `proof-gatekeeper` shapes. This server accepts both.
4. **Trap list:** the brief listed `INVALID_PROOF` as the 7th trap type;
   the event page / community builds list `AMOUNT_OVERFLOW` as the 7th.
   This server checks **both** (amount cap as a trap; an explicitly
   invalid incoming proof as `INVALID_PROOF`).
5. **Incoming-proof verification:** the envelope carries no proof bytes,
   so on-chain re-verification via zkVerifyJS is not wired (see above).
   The platform is the party that re-verifies proofs.

## Security notes

- The HMAC secret comes only from `AGENT_GAMES_HMAC_SECRET`. It is never
  logged, never committed, never pasted anywhere. Rotate it from the
  dashboard if it ever leaks — the old secret stops working immediately.
- `state.json` holds only proof_tx hashes and task IDs — no secrets.
- The server never holds a wallet key and cannot sign or send transactions.
- Every request is logged as one JSON line (timestamp, type, taskId,
  decision, reason, timings). Salt values and secrets are never logged.
- Responses are cached by task ID; the platform may retry a task after a
  network failure and will receive the identical signed body.

## References

- Official Build guide: https://agentgames.zkverify.io/build
- Circuit info (vk hashes + artifact URLs):
  https://agentgames.zkverify.io/api/circuit-info
- Community build that got a practice proof VERIFIED on Railway
  (reference for the wire format; this implementation is original code
  written from the protocol facts):
  https://github.com/lince00/agent-games-gatekeeper
- zkVerify docs: https://docs.zkverify.io (Kurier / zkVerifyJS)
