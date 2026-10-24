import { api, enrollment, LOGIN_AGAIN, messageFor, preAuth, session, show, withBusy } from "./api.js";

const pageMsg = document.getElementById("page-msg");
const enrollSection = document.getElementById("enroll-section");
const activateSection = document.getElementById("activate-section");
const backupSection = document.getElementById("backup-section");
const activateForm = document.getElementById("activate-form");
const activateMsg = document.getElementById("activate-msg");

const pre = preAuth.get();
if (!pre) window.location.replace("index.html");

function groupsOf4(secret) {
  return secret.match(/.{1,4}/g).join(" ");
}

function renderEnrollment(data) {
  document.getElementById("qr").src = data.qrSvg;
  document.getElementById("secret").textContent = groupsOf4(data.secret);
  document.getElementById("copy-secret").onclick = () => navigator.clipboard.writeText(data.secret);
  enrollSection.hidden = false;
  activateSection.hidden = false;
  activateForm.code.focus();
}

async function startEnrollment() {
  // Reuse the QR across reloads: enrolling again would generate a new secret
  // and invalidate the one already scanned.
  const saved = enrollment.get();
  if (saved && saved.token === pre.token) return renderEnrollment(saved);

  try {
    const res = await api("/2fa/enroll", { token: pre.token });
    const data = { token: pre.token, otpauthUri: res.otpauth_uri, secret: res.secret, qrSvg: res.qr_svg };
    enrollment.set(data);
    renderEnrollment(data);
  } catch (err) {
    show(pageMsg, messageFor(err));
    if (LOGIN_AGAIN.has(err.error)) setTimeout(() => window.location.replace("index.html"), 2500);
  }
}

activateForm.addEventListener("submit", (event) => {
  event.preventDefault();
  withBusy(activateForm.querySelector("button"), async () => {
    try {
      const res = await api("/2fa/activate", { token: pre.token, body: { code: activateForm.code.value } });
      session.set({ token: res.access_token, method: res.mfa_method, window: res.window });
      preAuth.clear();
      enrollment.clear();
      showBackupCodes(res.backup_codes);
    } catch (err) {
      show(activateMsg, messageFor(err));
      activateForm.code.select();
      if (LOGIN_AGAIN.has(err.error)) setTimeout(() => window.location.replace("index.html"), 2500);
    }
  });
});

function showBackupCodes(codes) {
  enrollSection.hidden = true;
  activateSection.hidden = true;
  const list = document.getElementById("backup-codes");
  list.replaceChildren(...codes.map((c) => Object.assign(document.createElement("li"), { textContent: c })));
  document.getElementById("copy-codes").onclick = () => navigator.clipboard.writeText(codes.join("\n"));
  document.getElementById("go-vault").onclick = () => window.location.assign("vault.html");
  backupSection.hidden = false;
}

if (pre) startEnrollment();
