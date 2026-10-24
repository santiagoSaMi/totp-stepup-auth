import * as Clipboard from "expo-clipboard";
import { useMemo, useState } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";

import type { StoredAccount } from "../storage/accounts";
import { mono, useTheme } from "../theme";
import { secondsRemaining, timeCounter, totp } from "../totp/totp";
import { CountdownBar } from "./CountdownBar";

interface Props {
  account: StoredAccount;
  now: number;
  onDelete: (account: StoredAccount) => void;
}

const WARNING_SECONDS = 5;

function formatCode(code: string): string {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

export function CodeCard({ account, now, onDelete }: Props) {
  const theme = useTheme();
  // Remember which code was copied: the label disappears by itself when the code changes.
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  // Only recompute the HMAC when the window changes, not on every tick.
  const counter = timeCounter(now, account.period);
  const code = useMemo(
    () => totp(account.secret, counter * account.period * 1000, account),
    [account, counter],
  );

  const remaining = secondsRemaining(now, account.period);
  const fraction = (account.period * 1000 - (now % (account.period * 1000))) / (account.period * 1000);
  const warning = remaining <= WARNING_SECONDS;
  const copied = copiedCode === code;

  async function copy() {
    await Clipboard.setStringAsync(code);
    setCopiedCode(code);
  }

  return (
    <Pressable
      onPress={copy}
      onLongPress={() => onDelete(account)}
      accessibilityRole="button"
      accessibilityLabel={`Código de ${account.account}: ${code.split("").join(" ")}. Toca para copiar.`}
      style={({ pressed }) => [
        styles.card,
        { backgroundColor: theme.surface, borderColor: theme.border, opacity: pressed ? 0.85 : 1 },
      ]}
    >
      <View style={styles.header}>
        <Text style={[styles.issuer, { color: theme.text }]} numberOfLines={1}>
          {account.issuer || account.account}
        </Text>
        <Text style={[styles.copied, { color: theme.ok }]}>{copied ? "Copiado" : ""}</Text>
      </View>
      {account.issuer ? (
        <Text style={[styles.account, { color: theme.muted }]} numberOfLines={1}>
          {account.account}
        </Text>
      ) : null}

      <Text style={[styles.code, mono, { color: warning ? theme.warn : theme.text }]}>{formatCode(code)}</Text>

      <CountdownBar fraction={fraction} warning={warning} />
      <Text style={[styles.remaining, mono, { color: theme.muted }]}>{remaining}s</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  card: { borderWidth: 1, borderRadius: 14, padding: 18, gap: 6 },
  header: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", gap: 8 },
  issuer: { fontSize: 17, fontWeight: "600", flexShrink: 1 },
  account: { fontSize: 14 },
  copied: { fontSize: 13, fontWeight: "600" },
  code: { fontSize: 46, fontWeight: "700", letterSpacing: 4, marginVertical: 6 },
  remaining: { fontSize: 13, textAlign: "right" },
});
