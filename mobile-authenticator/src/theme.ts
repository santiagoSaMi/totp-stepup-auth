import { Platform, useColorScheme } from "react-native";

const light = {
  bg: "#f5f6f8",
  surface: "#ffffff",
  text: "#1c2230",
  muted: "#5d6677",
  border: "#dde1e8",
  accent: "#3554d1",
  accentText: "#ffffff",
  track: "#e3e6ec",
  warn: "#c77700",
  error: "#a12626",
  errorBg: "#fdecec",
  ok: "#1d6b3a",
};

const dark: typeof light = {
  bg: "#12151c",
  surface: "#1b2029",
  text: "#e6e9ef",
  muted: "#9aa3b2",
  border: "#2d3442",
  accent: "#7b93ff",
  accentText: "#0e1220",
  track: "#2a303c",
  warn: "#ffb347",
  error: "#ffaaaa",
  errorBg: "#3a1a1a",
  ok: "#8fdca9",
};

export type Theme = typeof light;

export function useTheme(): Theme {
  return useColorScheme() === "dark" ? dark : light;
}

// Native fontFamily takes one font name; only web understands a CSS font stack.
export const mono = {
  fontFamily: Platform.select({ ios: "Menlo", android: "monospace", default: "ui-monospace, Menlo, Consolas, monospace" }),
  fontVariant: ["tabular-nums" as const],
};
