/**
 * login.ts — Login page + mandatory password change.
 */

import { initI18n } from "./i18n";
import { passkeySupported, loginWithPasskey } from "./passkey";

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

async function post(url: string, body: unknown): Promise<{ ok: boolean; status: number; data: any }> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

function showChangeView(): void {
  $("login-view").style.display = "none";
  $("change-view").style.display = "";
}

// ── PIN login (scrambled keypad) ──────────────────────────────────────
let pinChallengeId = "";
let pinPositions: number[] = [];

function renderPinMask(): void {
  const dots = pinPositions.map(() => "●").join(" ");
  $("pin-mask").textContent = dots || "· · · ·";
}

async function loadPinKeypad(): Promise<void> {
  const email = ($("pin-email") as HTMLInputElement).value.trim();
  $("pin-error").textContent = "";
  pinPositions = [];
  renderPinMask();
  const keypad = $("pin-keypad");
  keypad.innerHTML = "";
  try {
    const r = await fetch(`/api/auth/pin-challenge?email=${encodeURIComponent(email)}`);
    const data = await r.json().catch(() => ({}));
    if (!r.ok || !Array.isArray(data.layout)) {
      $("pin-error").textContent = data.error || "Clavier indisponible.";
      return;
    }
    pinChallengeId = data.challengeId;
    // data.layout[position] = displayed digit; we send the clicked POSITION.
    (data.layout as number[]).forEach((digit, position) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "btn btn-ghost";
      b.textContent = String(digit);
      b.style.cssText = "font-size:18px;padding:14px 0;justify-content:center";
      b.onclick = () => {
        if (pinPositions.length >= 6) return;
        pinPositions.push(position);
        renderPinMask();
      };
      keypad.appendChild(b);
    });
  } catch {
    $("pin-error").textContent = "Clavier indisponible.";
  }
}

function showPinView(prefillEmail: string): void {
  $("login-view").style.display = "none";
  $("pin-view").style.display = "";
  ($("pin-email") as HTMLInputElement).value = prefillEmail;
  void loadPinKeypad();
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  // Shows the OAuth/OIDC button if it is configured server-side
  fetch("/api/auth/oidc/status")
    .then((r) => (r.ok ? r.json() : null))
    .then((s) => {
      if (s && s.enabled) $("oidc-block").style.display = "";
    })
    .catch(() => {});
  // If already logged in, redirect
  fetch("/api/auth/me")
    .then((r) => (r.ok ? r.json() : null))
    .then((me) => {
      if (me && !me.mustChangePassword) location.href = "/";
      else if (me && me.mustChangePassword) showChangeView();
    })
    .catch(() => {});

  ($("login-form") as HTMLFormElement).onsubmit = async (e) => {
    e.preventDefault();
    const btn = $("login-btn") as HTMLButtonElement;
    btn.disabled = true;
    $("login-error").textContent = "";
    const email = ($("email") as HTMLInputElement).value.trim();
    const password = ($("password") as HTMLInputElement).value;
    const { ok, data } = await post("/api/auth/login", { email, password });
    btn.disabled = false;
    if (!ok) {
      $("login-error").textContent = data.error || "Échec de la connexion.";
      return;
    }
    if (data.mustChangePassword) {
      ($("cur-pw") as HTMLInputElement).value = password; // pre-filled for convenience
      showChangeView();
    } else {
      location.href = "/";
    }
  };

  // Passkey login (WebAuthn) — button shown if the browser supports it
  if (passkeySupported()) {
    $("passkey-block").style.display = "";
    $("passkey-login-btn").onclick = async () => {
      const btn = $("passkey-login-btn") as HTMLButtonElement;
      btn.disabled = true;
      $("passkey-error").textContent = "";
      try {
        await loginWithPasskey(($("email") as HTMLInputElement).value.trim());
        location.href = "/";
      } catch (err) {
        $("passkey-error").textContent = (err as Error).message || "Échec de la connexion.";
      } finally {
        btn.disabled = false;
      }
    };
  }

  // Toggle password ↔ PIN
  $("to-pin").onclick = (e) => {
    e.preventDefault();
    showPinView(($("email") as HTMLInputElement).value.trim());
  };
  $("to-password").onclick = (e) => {
    e.preventDefault();
    $("pin-view").style.display = "none";
    $("login-view").style.display = "";
  };
  $("pin-email").onchange = () => void loadPinKeypad();
  $("pin-back").onclick = () => { pinPositions.pop(); renderPinMask(); };
  $("pin-reshuffle").onclick = () => void loadPinKeypad();
  $("pin-submit").onclick = async () => {
    const email = ($("pin-email") as HTMLInputElement).value.trim();
    $("pin-error").textContent = "";
    if (pinPositions.length < 4) { $("pin-error").textContent = "Saisissez votre PIN (4 à 6 chiffres)."; return; }
    const btn = $("pin-submit") as HTMLButtonElement;
    btn.disabled = true;
    const { ok, data } = await post("/api/auth/pin-login", {
      email, challengeId: pinChallengeId, positions: pinPositions,
    });
    btn.disabled = false;
    if (!ok) {
      $("pin-error").textContent = data.error || "Échec de la connexion.";
      void loadPinKeypad(); // new scrambled keypad after failure
      return;
    }
    location.href = "/";
  };

  ($("change-form") as HTMLFormElement).onsubmit = async (e) => {
    e.preventDefault();
    const btn = $("change-btn") as HTMLButtonElement;
    btn.disabled = true;
    $("change-error").textContent = "";
    const currentPassword = ($("cur-pw") as HTMLInputElement).value;
    const newPassword = ($("new-pw") as HTMLInputElement).value;
    const { ok, data } = await post("/api/auth/change-password", { currentPassword, newPassword });
    btn.disabled = false;
    if (!ok) {
      $("change-error").textContent = data.error || "Échec du changement.";
      return;
    }
    location.href = "/";
  };
});
