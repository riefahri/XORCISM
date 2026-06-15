/**
 * reset.ts — New password choice (e-mail link), multilingual (initI18n).
 */
import { initI18n, t } from "./i18n";

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  const token = new URLSearchParams(location.search).get("token") || "";
  const form = document.getElementById("f") as HTMLFormElement;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = document.getElementById("err")!;
    err.textContent = "";
    const newPassword = (document.getElementById("password") as HTMLInputElement).value;
    const r = await fetch("/api/auth/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, newPassword }),
    });
    const d = (await r.json().catch(() => ({}))) as { error?: string };
    if (r.ok) location.href = "/";
    else err.textContent = d.error || t("common.error");
  });
});
