import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";

import { CodeCard } from "../components/CodeCard";
import { useNow } from "../hooks/useNow";
import type { StoredAccount } from "../storage/accounts";
import { mono, useTheme } from "../theme";

interface Props {
  accounts: StoredAccount[];
  notice: string | null;
  onAdd: () => void;
  onDelete: (account: StoredAccount) => void;
}

const pad = (n: number) => String(n).padStart(2, "0");

function clock(ms: number): string {
  const d = new Date(ms);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function CodesScreen({ accounts, notice, onAdd, onDelete }: Props) {
  const theme = useTheme();
  const now = useNow();

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={[styles.title, { color: theme.text }]}>Authenticator</Text>
        {/* Shown so clock skew between phone and server is visible during the demo. */}
        <Text style={[styles.clock, mono, { color: theme.muted }]}>Hora del dispositivo {clock(now)}</Text>
      </View>

      {notice ? <Text style={[styles.notice, { color: theme.ok }]}>{notice}</Text> : null}

      <ScrollView contentContainerStyle={styles.list}>
        {accounts.length === 0 ? (
          <View style={[styles.empty, { borderColor: theme.border }]}>
            <Text style={[styles.emptyTitle, { color: theme.text }]}>Aún no hay cuentas</Text>
            <Text style={[styles.emptyText, { color: theme.muted }]}>
              Escanea el QR que muestra la web al activar el 2FA, o pega la clave en Base32.
            </Text>
          </View>
        ) : (
          accounts.map((account) => <CodeCard key={account.id} account={account} now={now} onDelete={onDelete} />)
        )}
        {accounts.length > 0 ? (
          <Text style={[styles.hint, { color: theme.muted }]}>Toca un código para copiarlo · mantén presionado para eliminar</Text>
        ) : null}
      </ScrollView>

      <Pressable
        onPress={onAdd}
        accessibilityRole="button"
        style={({ pressed }) => [styles.addButton, { backgroundColor: theme.accent, opacity: pressed ? 0.85 : 1 }]}
      >
        <Text style={[styles.addText, { color: theme.accentText }]}>Agregar cuenta</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, paddingHorizontal: 16 },
  header: { paddingTop: 12, paddingBottom: 12, gap: 2 },
  title: { fontSize: 28, fontWeight: "700" },
  clock: { fontSize: 13 },
  notice: { fontSize: 14, fontWeight: "600", paddingBottom: 8 },
  list: { gap: 12, paddingBottom: 16 },
  empty: { borderWidth: 1, borderStyle: "dashed", borderRadius: 14, padding: 24, gap: 6, alignItems: "center" },
  emptyTitle: { fontSize: 17, fontWeight: "600" },
  emptyText: { fontSize: 14, textAlign: "center" },
  hint: { fontSize: 12, textAlign: "center", marginTop: 4 },
  addButton: { borderRadius: 12, paddingVertical: 14, alignItems: "center", marginBottom: 12 },
  addText: { fontSize: 16, fontWeight: "700" },
});
