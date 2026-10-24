import { api, messageFor, session, show } from "./api.js";

const msg = document.getElementById("vault-msg");
const current = session.get();

const WINDOW_TEXT = {
  "C-1": "C-1 (reloj del teléfono atrasado, o código enviado justo tras el cambio)",
  C: "C (relojes sincronizados)",
  "C+1": "C+1 (reloj del teléfono adelantado)",
};

function startCountdown(expiresAt) {
  const el = document.getElementById("expires");
  const tick = () => {
    const left = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
    el.textContent = `${Math.floor(left / 60)}m ${String(left % 60).padStart(2, "0")}s`;
    if (left === 0) show(msg, "La sesión expiró. Inicia sesión de nuevo.", "warn");
  };
  tick();
  setInterval(tick, 1000);
}

async function load() {
  if (!current) {
    show(msg, "No hay sesión con segundo factor. Inicia sesión primero.");
    return;
  }
  try {
    const vault = await api("/api/boveda-secreta", { method: "GET", token: current.token });
    document.getElementById("welcome").textContent = vault.message;
    document.getElementById("treasure").textContent = vault.treasure;
    document.getElementById("mfa-verified").textContent = String(vault.mfa_verified);
    document.getElementById("mfa-method").textContent = vault.mfa_method === "backup" ? "código de respaldo" : "TOTP";
    document.getElementById("window").textContent = current.window ? WINDOW_TEXT[current.window] : "—";
    startCountdown(vault.token_expires_at);
    document.getElementById("vault").hidden = false;
  } catch (err) {
    session.clear();
    show(msg, messageFor(err));
  }
}

load();
