/**
 * register.ts — Registration page (self-service), multilingual (initI18n).
 */
import { initI18n, t } from "./i18n";

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  const form = document.getElementById("f") as HTMLFormElement;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = document.getElementById("err")!;
    err.textContent = "";
    const body = {
      email: (document.getElementById("email") as HTMLInputElement).value.trim(),
      displayName: (document.getElementById("name") as HTMLInputElement).value.trim(),
      password: (document.getElementById("password") as HTMLInputElement).value,
      website: (document.getElementById("website") as HTMLInputElement).value, // honeypot
    };
    const r = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const d = (await r.json().catch(() => ({}))) as { error?: string };
    if (r.ok) location.href = "/";
    else err.textContent = d.error || t("common.error");
  });
});
