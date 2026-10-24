import { api, logout, messageFor, preAuth, show, withBusy } from "./api.js";

const loginForm = document.getElementById("login-form");
const loginMsg = document.getElementById("login-msg");
const registerForm = document.getElementById("register-form");
const registerMsg = document.getElementById("register-msg");

logout(); // landing on the login page always starts a fresh session

loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const { username, password } = Object.fromEntries(new FormData(loginForm));
  withBusy(loginForm.querySelector("button"), async () => {
    try {
      const res = await api("/auth/login", { body: { username, password } });
      preAuth.set({ token: res.pre_auth_token, username, nextStep: res.next_step });
      window.location.href = res.next_step === "verify-2fa" ? "verify.html" : "enroll.html";
    } catch (err) {
      show(loginMsg, messageFor(err));
    }
  });
});

registerForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const { username, password } = Object.fromEntries(new FormData(registerForm));
  withBusy(registerForm.querySelector("button"), async () => {
    try {
      const user = await api("/auth/register", { body: { username, password } });
      show(registerMsg, `Cuenta "${user.username}" creada. Ahora inicia sesión.`, "ok");
      loginForm.username.value = user.username;
      loginForm.password.focus();
      registerForm.reset();
    } catch (err) {
      show(registerMsg, messageFor(err));
    }
  });
});
