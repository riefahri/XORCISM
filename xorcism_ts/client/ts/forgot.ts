/**
 * forgot.ts — Password reset request, multilingual (initI18n).
 * Always a generic response (anti-enumeration): we show the "sent" message.
 */
import { initI18n } from "./i18n";

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  const form = document.getElementById("f") as HTMLFormElement;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const email = (document.getElementById("email") as HTMLInputElement).value.trim();
    await fetch("/api/auth/forgot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    document.getElementById("form-wrap")!.style.display = "none";
    document.getElementById("sent")!.style.display = "";
  });
});
