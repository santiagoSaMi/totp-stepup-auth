import { CameraView, useCameraPermissions, type BarcodeScanningResult } from "expo-camera";
import { useRef, useState } from "react";
import { KeyboardAvoidingView, Platform, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";

import { mono, useTheme, type Theme } from "../theme";
import { accountFromInput, isOtpAuthUri, parseOtpAuthUri, type OtpAccount } from "../totp/otpauth";

interface Props {
  onSave: (account: OtpAccount) => void;
  onCancel: () => void;
}

function Button({ label, onPress, theme, secondary = false }: { label: string; onPress: () => void; theme: Theme; secondary?: boolean }) {
  return (
    <Pressable
      onPress={onPress}
      accessibilityRole="button"
      style={({ pressed }) => [
        styles.button,
        secondary
          ? { borderWidth: 1, borderColor: theme.border, backgroundColor: "transparent" }
          : { backgroundColor: theme.accent },
        { opacity: pressed ? 0.85 : 1 },
      ]}
    >
      <Text style={[styles.buttonText, { color: secondary ? theme.accent : theme.accentText }]}>{label}</Text>
    </Pressable>
  );
}

function Scanner({ onScanned, onClose, theme }: { onScanned: (data: string) => string | null; onClose: () => void; theme: Theme }) {
  const [permission, requestPermission] = useCameraPermissions();
  const [error, setError] = useState<string | null>(null);
  // onBarcodeScanned fires many times per second; handle one QR at a time.
  const busy = useRef(false);

  function handleScan({ data }: BarcodeScanningResult) {
    if (busy.current) return;
    busy.current = true;
    const problem = onScanned(data);
    if (problem) {
      setError(problem);
      setTimeout(() => (busy.current = false), 1500);
    }
  }

  if (!permission) return <Text style={{ color: theme.muted }}>Comprobando permiso de cámara…</Text>;

  if (!permission.granted) {
    return (
      <View style={styles.section}>
        <Text style={{ color: theme.text }}>La app necesita la cámara para leer el código QR.</Text>
        <Button label="Permitir cámara" onPress={requestPermission} theme={theme} />
        <Button label="Volver" onPress={onClose} theme={theme} secondary />
      </View>
    );
  }

  return (
    <View style={styles.section}>
      <View style={styles.cameraFrame}>
        <CameraView
          style={StyleSheet.absoluteFill}
          facing="back"
          barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
          onBarcodeScanned={handleScan}
        />
      </View>
      <Text style={{ color: error ? theme.error : theme.muted, textAlign: "center" }}>
        {error ?? "Apunta al código QR de la página de activación"}
      </Text>
      <Button label="Cancelar escaneo" onPress={onClose} theme={theme} secondary />
    </View>
  );
}

export function AddAccountScreen({ onSave, onCancel }: Props) {
  const theme = useTheme();
  const [scanning, setScanning] = useState(false);
  const [text, setText] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const looksLikeUri = isOtpAuthUri(text);

  function handleScanned(data: string): string | null {
    try {
      onSave(parseOtpAuthUri(data));
      return null;
    } catch (e) {
      return `QR no válido: ${(e as Error).message}`;
    }
  }

  function saveManual() {
    if (!text.trim()) {
      setError("Pega la clave o la URI otpauth://");
      return;
    }
    try {
      onSave(accountFromInput(text, name));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <KeyboardAvoidingView style={styles.container} behavior={Platform.OS === "ios" ? "padding" : undefined}>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Text style={[styles.title, { color: theme.text }]}>Agregar cuenta</Text>

        {scanning ? (
          <Scanner onScanned={handleScanned} onClose={() => setScanning(false)} theme={theme} />
        ) : (
          <>
            <View style={[styles.card, { backgroundColor: theme.surface, borderColor: theme.border }]}>
              <Text style={[styles.cardTitle, { color: theme.text }]}>Escanear código QR</Text>
              <Text style={{ color: theme.muted }}>Lee la URI otpauth:// que muestra la web al activar el 2FA.</Text>
              <Button label="Abrir cámara" onPress={() => setScanning(true)} theme={theme} />
            </View>

            <View style={[styles.card, { backgroundColor: theme.surface, borderColor: theme.border }]}>
              <Text style={[styles.cardTitle, { color: theme.text }]}>Ingresar clave manualmente</Text>
              <Text style={{ color: theme.muted }}>Pega la clave en Base32 o la URI completa.</Text>
              <TextInput
                value={text}
                onChangeText={(value) => {
                  setText(value);
                  setError(null);
                }}
                placeholder="JBSW Y3DP EHPK 3PXP…  u  otpauth://totp/…"
                placeholderTextColor={theme.muted}
                autoCapitalize="characters"
                autoCorrect={false}
                spellCheck={false}
                multiline
                style={[styles.input, mono, { color: theme.text, borderColor: theme.border, backgroundColor: theme.bg }]}
              />
              {!looksLikeUri ? (
                <TextInput
                  value={name}
                  onChangeText={setName}
                  placeholder="Nombre de la cuenta (ej. Lab2FA alice)"
                  placeholderTextColor={theme.muted}
                  autoCorrect={false}
                  style={[styles.input, { color: theme.text, borderColor: theme.border, backgroundColor: theme.bg }]}
                />
              ) : null}
              {error ? (
                <Text style={[styles.error, { color: theme.error, backgroundColor: theme.errorBg }]}>{error}</Text>
              ) : null}
              <Button label="Guardar" onPress={saveManual} theme={theme} />
            </View>
          </>
        )}

        <Button label="Volver" onPress={onCancel} theme={theme} secondary />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  content: { padding: 16, gap: 16 },
  title: { fontSize: 28, fontWeight: "700" },
  section: { gap: 12 },
  card: { borderWidth: 1, borderRadius: 14, padding: 16, gap: 10 },
  cardTitle: { fontSize: 17, fontWeight: "600" },
  cameraFrame: { width: "100%", aspectRatio: 1, borderRadius: 14, overflow: "hidden", backgroundColor: "#000" },
  input: { borderWidth: 1, borderRadius: 10, padding: 12, fontSize: 15, minHeight: 48 },
  error: { borderRadius: 8, padding: 10, fontSize: 14 },
  button: { borderRadius: 12, paddingVertical: 13, alignItems: "center" },
  buttonText: { fontSize: 16, fontWeight: "700" },
});
