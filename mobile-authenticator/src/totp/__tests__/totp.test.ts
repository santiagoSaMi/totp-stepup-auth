import { decodeBase32, InvalidBase32Error } from "../base32";
import { accountFromInput, InvalidOtpAuthUriError, parseOtpAuthUri } from "../otpauth";
import { counterBytes, hotp, secondsRemaining, timeCounter, totp } from "../totp";

const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));

// Shared secret of the RFC 4226 / 6238 vectors: ASCII "12345678901234567890".
const RFC_KEY = ascii("12345678901234567890");
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("decodeBase32", () => {
  // RFC 4648, section 10.
  it.each([
    ["", ""],
    ["MY======", "f"],
    ["MZXQ====", "fo"],
    ["MZXW6===", "foo"],
    ["MZXW6YQ=", "foob"],
    ["MZXW6YTB", "fooba"],
    ["MZXW6YTBOI======", "foobar"],
  ])("decodes %p", (encoded, expected) => {
    expect(decodeBase32(encoded)).toEqual(ascii(expected));
  });

  it("decodes the RFC 6238 secret", () => {
    expect(decodeBase32(RFC_SECRET)).toEqual(RFC_KEY);
  });

  it("accepts lowercase, spaces, dashes and no padding", () => {
    expect(decodeBase32("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq")).toEqual(RFC_KEY);
    expect(decodeBase32("MZXW6YTBOI")).toEqual(ascii("foobar"));
  });

  it.each(["MZXW1", "MZXW0", "MZXW8", "MZ!W6"])("rejects invalid characters in %p", (bad) => {
    expect(() => decodeBase32(bad)).toThrow(InvalidBase32Error);
  });
});

describe("hotp", () => {
  // RFC 4226, Appendix D.
  const expected = [
    "755224", "287082", "359152", "969429", "338314",
    "254676", "287922", "162583", "399871", "520489",
  ];
  it.each(expected.map((code, counter) => [counter, code]))("counter %p -> %p", (counter, code) => {
    expect(hotp(RFC_KEY, counter as number)).toBe(code);
  });

  it("encodes the counter as 8 big-endian bytes", () => {
    expect(Array.from(counterBytes(1))).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(Array.from(counterBytes(2 ** 32 + 2))).toEqual([0, 0, 0, 1, 0, 0, 0, 2]);
  });
});

describe("totp", () => {
  // RFC 6238, Appendix B (SHA1, 30 s step).
  const vectors: [number, string][] = [
    [59, "94287082"],
    [1111111109, "07081804"],
    [1111111111, "14050471"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
    [20000000000, "65353130"],
  ];

  it.each(vectors)("t=%p -> %p (8 digits)", (t, code) => {
    expect(totp(RFC_SECRET, t * 1000, { digits: 8 })).toBe(code);
  });

  it.each(vectors)("t=%p -> last 6 digits of %p", (t, code) => {
    expect(totp(RFC_SECRET, t * 1000)).toBe(code.slice(-6));
  });

  // Generated with the Python backend (app.mfa.totp): both implementations must agree.
  it.each([
    [1700000000, "406058"],
    [1729771234, "441233"],
    [1761300000, "210869"],
  ])("matches the backend at t=%p", (t, code) => {
    expect(totp("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", t * 1000)).toBe(code);
  });

  it("keeps the code for a whole window and changes after it", () => {
    const start = 1_700_000_010_000 - (1_700_000_010_000 % 30_000);
    const code = totp(RFC_SECRET, start);
    expect(totp(RFC_SECRET, start + 29_999)).toBe(code);
    expect(totp(RFC_SECRET, start + 30_000)).not.toBe(code);
  });

  it("computes counter and countdown", () => {
    expect(timeCounter(59_000)).toBe(1);
    expect(secondsRemaining(30_000)).toBe(30);
    expect(secondsRemaining(59_000)).toBe(1);
    expect(secondsRemaining(45_500)).toBe(15);
  });
});

describe("parseOtpAuthUri", () => {
  it("parses the URI produced by the backend", () => {
    const uri =
      "otpauth://totp/Lab2FA:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Lab2FA&algorithm=SHA1&digits=6&period=30";
    expect(parseOtpAuthUri(uri)).toEqual({
      issuer: "Lab2FA",
      account: "alice",
      secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
      digits: 6,
      period: 30,
    });
  });

  it("handles percent-encoding, missing optional params and label-only issuer", () => {
    const parsed = parseOtpAuthUri("otpauth://totp/ACME%20Co%3Ajohn%40example.com?secret=jbswy3dpehpk3pxp");
    expect(parsed).toEqual({
      issuer: "ACME Co",
      account: "john@example.com",
      secret: "JBSWY3DPEHPK3PXP",
      digits: 6,
      period: 30,
    });
  });

  it.each([
    ["https://example.com", "otpauth"],
    ["otpauth://hotp/x?secret=JBSWY3DP", "totp"],
    ["otpauth://totp/x?issuer=a", "secret"],
    ["otpauth://totp/x?secret=NOT-BASE32!", "Base32"],
    ["otpauth://totp/x?secret=JBSWY3DP&algorithm=SHA256", "SHA1"],
    ["otpauth://totp/x?secret=JBSWY3DP&digits=7", "digits"],
  ])("rejects %p", (uri, reason) => {
    expect(() => parseOtpAuthUri(uri)).toThrow(InvalidOtpAuthUriError);
    expect(() => parseOtpAuthUri(uri)).toThrow(reason);
  });
});

describe("accountFromInput", () => {
  it("accepts a bare secret with a name", () => {
    expect(accountFromInput("jbsw y3dp ehpk 3pxp", "Mi cuenta")).toMatchObject({
      account: "Mi cuenta",
      secret: "JBSWY3DPEHPK3PXP",
    });
  });

  it("accepts a full URI", () => {
    expect(accountFromInput("  otpauth://totp/Lab2FA:bob?secret=JBSWY3DP ", "").account).toBe("bob");
  });
});
