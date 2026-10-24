// Shared helpers: HTTP calls, session storage and user-facing error messages.

export class ApiError extends Error {
  constructor(status, error, detail) {
    super(detail || error || `HTTP ${status}`);
    this.status = status;
    this.error = error;
  }
}

export async function api(path, { method = "POST", body, token } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // FastAPI validation errors come as {detail: [{msg, ...}]}.
    const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join("; ") : data.detail;
    throw new ApiError(res.status, data.error ?? (res.status === 422 ? "validation" : undefined), detail);
  }
  return data;
}

// sessionStorage is per tab and cleared when the tab closes.
function store(key) {
  return {
    get: () => {
      try { return JSON.parse(sessionStorage.getItem(key)); } catch { return null; }
    },
    set: (value) => {
      try { sessionStorage.setItem(key, JSON.stringify(value)); } catch {}
    },
    clear: () => {
      try { sessionStorage.removeItem(key); } catch {}
    },
  };
}

export const preAuth = store("preAuth"); // {token, username, nextStep}
export const session = store("session"); // {token, method, window}
export const enrollment = store("enrollment"); // {token, otpauthUri, secret, qrSvg}

export function logout() {
  preAuth.clear();
  session.clear();
  enrollment.clear();
}

// Errors that mean the pre_auth_token is no longer usable: go back to login.
export const LOGIN_AGAIN = new Set(["invalid_pre_auth", "pre_auth_token_used", "too_many_attempts"]);

const MESSAGES = {
  invalid_credentials: "Usuario o contraseña incorrectos.",
  username_taken: "Ese nombre de usuario ya existe.",
  invalid_code: "Código incorrecto.",
  replay_detected: "Este código ya fue usado: ataque de repetición bloqueado. Espera el siguiente código.",
  too_many_attempts: "Demasiados intentos fallidos. Inicia sesión de nuevo.",
  pre_auth_token_used: "Esta sesión temporal ya se usó. Inicia sesión de nuevo.",
  invalid_pre_auth: "La sesión temporal no es válida o expiró. Inicia sesión de nuevo.",
  invalid_token: "Token inválido o expirado.",
  invalid_state_transition: "La acción no es válida en el estado actual del 2FA.",
};

export function messageFor(err) {
  if (!(err instanceof ApiError)) return "No se pudo contactar al servidor.";
  if (err.error === "validation") return `Datos inválidos: ${err.message}`;
  return MESSAGES[err.error] ?? err.message;
}

export function show(el, text, kind = "error") {
  el.className = `alert ${kind}`;
  el.textContent = text;
}

export async function withBusy(button, fn) {
  button.disabled = true;
  try {
    return await fn();
  } finally {
    button.disabled = false;
  }
}
