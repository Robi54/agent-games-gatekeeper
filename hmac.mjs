// HMAC-SHA256 helpers for the Agent Games protocol.
//
// - Inbound: verify `x-agent-games-signature` against the RAW request body,
//   BEFORE any JSON parsing. Hex-encoded, lowercase.
// - Outbound: sign the exact raw response body bytes and send the hex digest
//   in the `x-agent-games-signature` response header.
//
// The lowercase-hex encoding is the standard HMAC-SHA256 convention; the
// /build page does not spell it out, so the dashboard preflight is the
// confirmation step for it (a wrong format fails preflight).
import { createHmac, timingSafeEqual } from "node:crypto";

/** HMAC-SHA256 hex digest of the raw body under `secret`. */
export function hmacHex(secret, rawBody) {
  return createHmac("sha256", secret).update(rawBody).digest("hex");
}

/** Timing-safe check of the inbound signature header against the raw body. */
export function verifySignature(secret, rawBody, headerValue) {
  if (!secret || typeof headerValue !== "string") return false;
  const expected = hmacHex(secret, rawBody);
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(headerValue.trim().toLowerCase(), "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
