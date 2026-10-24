// Accounts persist on the device only. Nothing is ever sent over the network.
//
// Native: expo-secure-store (iOS Keychain / Android Keystore).
// Web (Expo web, for development): localStorage, since secure-store has no web support.

import * as SecureStore from "expo-secure-store";
import { Platform } from "react-native";

import type { OtpAccount } from "../totp/otpauth";

export interface StoredAccount extends OtpAccount {
  id: string;
  addedAt: number;
}

const KEY = "totp_accounts_v1";

async function readRaw(): Promise<string | null> {
  if (Platform.OS === "web") {
    try {
      return globalThis.localStorage?.getItem(KEY) ?? null;
    } catch {
      return null;
    }
  }
  return SecureStore.getItemAsync(KEY);
}

async function writeRaw(value: string): Promise<void> {
  if (Platform.OS === "web") {
    try {
      globalThis.localStorage?.setItem(KEY, value);
    } catch {
      // private mode or storage disabled: accounts last until the tab closes
    }
    return;
  }
  await SecureStore.setItemAsync(KEY, value);
}

export async function loadAccounts(): Promise<StoredAccount[]> {
  const raw = await readRaw();
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export async function saveAccounts(accounts: StoredAccount[]): Promise<void> {
  await writeRaw(JSON.stringify(accounts));
}

function sameAccount(a: OtpAccount, b: OtpAccount): boolean {
  return a.issuer === b.issuer && a.account === b.account;
}

/**
 * Adds the account, or replaces the secret of an existing one with the same
 * issuer and name. Re-enrolling in the backend generates a new secret, and
 * the old code would otherwise sit next to the new one and never work.
 */
export function upsertAccount(
  accounts: StoredAccount[],
  account: OtpAccount,
): { accounts: StoredAccount[]; replaced: boolean } {
  const existing = accounts.find((a) => sameAccount(a, account));
  if (existing) {
    return {
      accounts: accounts.map((a) => (a.id === existing.id ? { ...a, ...account } : a)),
      replaced: true,
    };
  }
  const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  return { accounts: [...accounts, { ...account, id, addedAt: Date.now() }], replaced: false };
}
