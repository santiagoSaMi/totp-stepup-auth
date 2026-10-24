// TOTP (RFC 6238) on top of HOTP (RFC 4226), written by hand.
//
// The only library call is HMAC-SHA1 from @noble/hashes (allowed by the lab:
// it computes a hash, not a TOTP code). Counter encoding, dynamic truncation
// and the time windows are implemented here.

import { hmac } from "@noble/hashes/hmac.js";
import { sha1 } from "@noble/hashes/legacy.js";

import { decodeBase32 } from "./base32";

export const DEFAULT_PERIOD = 30;
export const DEFAULT_DIGITS = 6;

export interface TotpOptions {
  period?: number;
  digits?: number;
}

/** Counter as 8 bytes, big-endian. JS numbers are exact up to 2^53, plenty for unix time / 30. */
export function counterBytes(counter: number): Uint8Array {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);
  return bytes;
}

/** HOTP(K, C) = Truncate(HMAC-SHA1(K, C)) mod 10^digits */
export function hotp(key: Uint8Array, counter: number, digits: number = DEFAULT_DIGITS): string {
  const mac = hmac(sha1, key, counterBytes(counter)); // 20 bytes

  // Dynamic truncation: the low 4 bits of the last byte pick where to read
  // 4 bytes; the top bit is cleared to get a positive 31-bit integer.
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
    mac[offset + 3];

  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

/** T = floor(unix_seconds / period) */
export function timeCounter(unixMs: number, period: number = DEFAULT_PERIOD): number {
  return Math.floor(unixMs / 1000 / period);
}

/** Seconds until the code changes: period..1 */
export function secondsRemaining(unixMs: number, period: number = DEFAULT_PERIOD): number {
  return period - (Math.floor(unixMs / 1000) % period);
}

export function totp(secretBase32: string, unixMs: number = Date.now(), options: TotpOptions = {}): string {
  const { period = DEFAULT_PERIOD, digits = DEFAULT_DIGITS } = options;
  return hotp(decodeBase32(secretBase32), timeCounter(unixMs, period), digits);
}
