// Base32 decoder (RFC 4648), written by hand.
//
// Each character encodes 5 bits. We push them into an accumulator and emit a
// byte every time 8 or more bits are available.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export class InvalidBase32Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidBase32Error";
  }
}

/** Accepts lowercase, spaces, dashes and missing "=" padding, as people type secrets. */
export function normalizeBase32(input: string): string {
  return input.replace(/[\s-]/g, "").replace(/=+$/, "").toUpperCase();
}

export function decodeBase32(input: string): Uint8Array {
  const clean = normalizeBase32(input);
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (const char of clean) {
    const value = ALPHABET.indexOf(char);
    if (value === -1) {
      throw new InvalidBase32Error(`carácter no válido en la clave: "${char}"`);
    }
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >>> bits) & 0xff);
    }
    buffer &= (1 << bits) - 1; // keep only the bits not emitted yet
  }

  return Uint8Array.from(bytes);
}
