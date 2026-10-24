import { api, LOGIN_AGAIN, messageFor, preAuth, session, show, withBusy } from "./api.js";

const form = document.getElementById("verify-form");
const msg = document.getElementById("verify-msg");
// form.elements, not form.method: that is the <form method> attribute.
const { code: codeInput } = form.elements;

const pre = preAuth.get();
if (!pre) window.location.replace("index.html");

// Switch the input between a 6-digit TOTP and a backup code like K7QX2-MNP4R.
form.addEventListener("change", (event) => {
  if (event.target.name !== "method") return;
  const backup = event.target.value === "backup";
  Object.assign(codeInput, {
    value: "",
    maxLength: backup ? 11 : 6,
    placeholder: backup ? "XXXXX-XXXXX" : "000000",
    inputMode: backup ? "text" : "numeric",
  });
  codeInput.focus();
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const method = form.elements.method.value;
  withBusy(form.querySelector("button"), async () => {
    try {
      const res = await api("/auth/verify-2fa", { token: pre.token, body: { code: codeInput.value, method } });
      session.set({ token: res.access_token, method: res.mfa_method, window: res.window });
      preAuth.clear();
      window.location.assign("vault.html");
    } catch (err) {
      show(msg, messageFor(err), err.error === "replay_detected" ? "warn" : "error");
      codeInput.select();
      if (LOGIN_AGAIN.has(err.error)) setTimeout(() => window.location.replace("index.html"), 2500);
    }
  });
});

document.getElementById("try-vault").addEventListener("click", async () => {
  const out = document.getElementById("try-vault-msg");
  try {
    await api("/api/boveda-secreta", { method: "GET", token: pre.token });
    show(out, "¡La bóveda se abrió solo con la contraseña! Esto no debería pasar.");
  } catch (err) {
    show(out, `Acceso denegado (HTTP ${err.status}): ${err.message}. El pre_auth_token no abre recursos protegidos.`, "ok");
  }
});

codeInput.focus();
