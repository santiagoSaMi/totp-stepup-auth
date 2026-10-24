import { StyleSheet, View } from "react-native";

import { useTheme } from "../theme";

interface Props {
  /** 1 = full window left, 0 = about to change */
  fraction: number;
  warning: boolean;
}

export function CountdownBar({ fraction, warning }: Props) {
  const theme = useTheme();
  return (
    <View style={[styles.track, { backgroundColor: theme.track }]}>
      <View
        style={[
          styles.fill,
          { width: `${Math.max(0, Math.min(1, fraction)) * 100}%`, backgroundColor: warning ? theme.warn : theme.accent },
        ]}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  track: { height: 6, borderRadius: 3, overflow: "hidden" },
  fill: { height: "100%", borderRadius: 3 },
});
