/**
 * ask.ts — "Ask the threat model" page: queries the local AI (Ollama) via
 * /api/ai/ask, which does RAG over the XORCISM data (KEV/assets, ATT&CK, hunts).
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }

const EXAMPLES = [
  "Quelles sont les menaces les plus impactantes pour mon organisation ?",
  "Quels actifs sont exposés à des vulnérabilités activement exploitées (KEV) ?",
  "Quelles techniques ATT&CK devrais-je prioriser pour la détection ?",
  "Résume les hunts récents et ce qu'ils impliquent.",
];

async function refreshStatus(): Promise<void> {
  const el = $("ai-status");
  try {
    const s = await (await fetch("/api/ai/status")).json() as { reachable: boolean; model: string };
    if (s.reachable) { el.textContent = `🟢 Ollama · ${s.model}`; el.className = "ai-badge ai-up"; }
    else { el.textContent = "🔴 IA locale injoignable"; el.className = "ai-badge ai-down"; }
  } catch {
    el.textContent = "🔴 IA locale injoignable"; el.className = "ai-badge ai-down";
  }
}

async function ask(): Promise<void> {
  const q = ($("ask-q") as HTMLTextAreaElement).value.trim();
  if (!q) return;
  const out = $("ask-answer");
  const src = $("ask-sources");
  const btn = $("ask-btn") as HTMLButtonElement;
  out.textContent = "⏳ L'IA locale réfléchit (cela peut prendre quelques secondes)…";
  src.textContent = "";
  btn.disabled = true;
  try {
    const r = await fetch("/api/ai/ask", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question: q }),
    });
    const d = await r.json() as { answer?: string; sources?: string[]; model?: string; error?: string };
    if (!r.ok) { out.textContent = "⚠️ " + (d.error || `Erreur ${r.status}`); }
    else {
      out.textContent = d.answer || "(réponse vide)";
      src.textContent = (d.sources && d.sources.length)
        ? `Contexte XORCISM utilisé : ${d.sources.join(", ")} · modèle : ${d.model}`
        : `Aucune donnée org spécifique trouvée · modèle : ${d.model}`;
    }
  } catch (e) {
    out.textContent = "⚠️ " + String(e);
  } finally {
    btn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  const ex = $("ask-examples");
  for (const e of EXAMPLES) {
    const b = document.createElement("button");
    b.textContent = e;
    b.onclick = () => { ($("ask-q") as HTMLTextAreaElement).value = e; void ask(); };
    ex.appendChild(b);
  }
  $("ask-btn").onclick = () => void ask();
  ($("ask-q") as HTMLTextAreaElement).addEventListener("keydown", (e) => {
    if ((e as KeyboardEvent).key === "Enter" && (e as KeyboardEvent).ctrlKey) { e.preventDefault(); void ask(); }
  });
  void refreshStatus();
});
