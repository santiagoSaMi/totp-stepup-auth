// Parser for Key URIs: otpauth://totp/Issuer:account?secret=...&issuer=...
//
// Parsed by hand instead of with `URL`, whose React Native implementation
// does not fully support custom schemes and searchParams.

import { decodeBase32, InvalidBase32Error, normalizeBase32 } from "./base32";
import { DEFAULT_DIGITS, DEFAULT_PERIOD } from "./totp";

export interface OtpAccount {
  issuer: string;
  account: string;
  secret: string; // normalized Base32
  digits: number;
  period: number;
}

export class InvalidOtpAuthUriError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidOtpAuthUriError";
  }
}

const URI_PATTERN = /^otpauth:\/\/([^/?#]+)\/([^?#]*)(?:\?([^#]*))?/i;

function decode(component: string): string {
  try {
    return decodeURIComponent(component.replace(/\+/g, " "));
  } catch {
    throw new InvalidOtpAuthUriError("la URI tiene caracteres mal codificados");
  }
}

function parseQuery(query: string): Map<string, string> {
  const params = new Map<string, string>();
  for (const pair of query.split("&")) {
    if (!pair) continue;
    const [key, ...rest] = pair.split("=");
    params.set(decode(key).toLowerCase(), decode(rest.join("=")));
  }
  return params;
}

function validSecret(raw: string): string {
  const secret = normalizeBase32(raw);
  try {
    if (decodeBase32(secret).length === 0) throw new InvalidBase32Error("vacía");
  } catch (e) {
    throw new InvalidOtpAuthUriError(`la clave no es Base32 válida (${(e as Error).message})`);
  }
  return secret;
}

export function isOtpAuthUri(text: string): boolean {
  return text.trim().toLowerCase().startsWith("otpauth://");
}

export function parseOtpAuthUri(uri: string): OtpAccount {
  const match = URI_PATTERN.exec(uri.trim());
  if (!match) throw new InvalidOtpAuthUriError("no es una URI otpauth://");

  const [, type, rawLabel, query = ""] = match;
  if (type.toLowerCase() !== "totp") {
    throw new InvalidOtpAuthUriError(`tipo "${type}" no soportado; solo totp`);
  }

  const params = parseQuery(query);
  const secret = params.get("secret");
  if (!secret) throw new InvalidOtpAuthUriError("falta el parámetro secret");

  const algorithm = (params.get("algorithm") ?? "SHA1").toUpperCase();
  if (algorithm !== "SHA1") {
    throw new InvalidOtpAuthUriError(`algoritmo ${algorithm} no soportado; solo SHA1`);
  }

  const digits = Number(params.get("digits") ?? DEFAULT_DIGITS);
  if (digits !== 6 && digits !== 8) throw new InvalidOtpAuthUriError("digits debe ser 6 u 8");

  const period = Number(params.get("period") ?? DEFAULT_PERIOD);
  if (!Number.isInteger(period) || period <= 0) throw new InvalidOtpAuthUriError("period no es válido");

  // Label is "Issuer:account" or just "account"; the issuer parameter wins.
  const label = decode(rawLabel);
  const colon = label.indexOf(":");
  const labelIssuer = colon >= 0 ? label.slice(0, colon).trim() : "";
  const account = (colon >= 0 ? label.slice(colon + 1) : label).trim();

  return {
    issuer: params.get("issuer")?.trim() || labelIssuer,
    account,
    secret: validSecret(secret),
    digits,
    period,
  };
}

/** For the manual field: a full otpauth:// URI, or a bare Base32 secret plus a name. */
export function accountFromInput(text: string, name: string): OtpAccount {
  if (isOtpAuthUri(text)) return parseOtpAuthUri(text);
  return {
    issuer: "",
    account: name.trim() || "Cuenta",
    secret: validSecret(text),
    digits: DEFAULT_DIGITS,
    period: DEFAULT_PERIOD,
  };
}
