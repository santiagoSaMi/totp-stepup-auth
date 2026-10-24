import { StatusBar } from "expo-status-bar";
import { useEffect, useRef, useState } from "react";
import { ActivityIndicator, StyleSheet, View } from "react-native";
import { SafeAreaProvider, SafeAreaView } from "react-native-safe-area-context";

import { confirm } from "./src/confirm";
import { AddAccountScreen } from "./src/screens/AddAccountScreen";
import { CodesScreen } from "./src/screens/CodesScreen";
import { loadAccounts, saveAccounts, upsertAccount, type StoredAccount } from "./src/storage/accounts";
import { useTheme } from "./src/theme";
import type { OtpAccount } from "./src/totp/otpauth";

type Screen = "codes" | "add";

function Main() {
  const theme = useTheme();
  const [accounts, setAccounts] = useState<StoredAccount[] | null>(null);
  const [screen, setScreen] = useState<Screen>("codes");
  const [notice, setNotice] = useState<string | null>(null);
  const noticeTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => {
    loadAccounts().then(setAccounts);
  }, []);

  function flash(message: string) {
    setNotice(message);
    clearTimeout(noticeTimer.current);
    noticeTimer.current = setTimeout(() => setNotice(null), 3000);
  }

  async function update(next: StoredAccount[]) {
    setAccounts(next);
    await saveAccounts(next);
  }

  async function handleSave(account: OtpAccount) {
    const result = upsertAccount(accounts ?? [], account);
    await update(result.accounts);
    const label = account.issuer ? `${account.issuer} (${account.account})` : account.account;
    flash(result.replaced ? `Clave de ${label} actualizada` : `${label} agregada`);
    setScreen("codes");
  }

  async function handleDelete(account: StoredAccount) {
    const ok = await confirm(
      "Eliminar cuenta",
      `¿Eliminar ${account.issuer || account.account}? Ya no podrás generar sus códigos.`,
      "Eliminar",
    );
    if (ok) await update((accounts ?? []).filter((a) => a.id !== account.id));
  }

  return (
    <SafeAreaView style={[styles.root, { backgroundColor: theme.bg }]}>
      <StatusBar style="auto" />
      {accounts === null ? (
        <View style={styles.loading}>
          <ActivityIndicator color={theme.accent} />
        </View>
      ) : screen === "codes" ? (
        <CodesScreen accounts={accounts} notice={notice} onAdd={() => setScreen("add")} onDelete={handleDelete} />
      ) : (
        <AddAccountScreen onSave={handleSave} onCancel={() => setScreen("codes")} />
      )}
    </SafeAreaView>
  );
}

export default function App() {
  return (
    <SafeAreaProvider>
      <Main />
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  loading: { flex: 1, alignItems: "center", justifyContent: "center" },
});
