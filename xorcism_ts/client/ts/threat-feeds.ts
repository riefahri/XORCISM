/** threat-feeds.ts — /threat-feeds CTI reader, fully i18n'd (ported from the page's inline script). */
import { initI18n, t, applyTranslations } from "./i18n";

interface Feed { id: number | string; name: string; vendor?: string; url?: string; site?: string; category?: string }
interface Item { title: string; summary?: string; source?: string; date?: string; link?: string }

let feeds: Feed[] = [];
let current: string = "latest";
let currentItems: Item[] = [];
const newsEl = (): HTMLElement => document.getElementById("tf-news")!;
const sideEl = (): HTMLElement => document.getElementById("tf-side")!;

function esc(s: unknown): string { const d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }
function host(u: string): string { try { return new URL(u).host.replace(/^www\./, ""); } catch { return ""; } }
function rel(iso?: string): string {
  if (!iso) return "";
  const tt = Date.parse(iso); if (isNaN(tt)) return esc(iso);
  const s = Math.floor((Date.now() - tt) / 1000);
  if (s < 60) return t("tf.now");
  if (s < 3600) return Math.floor(s / 60) + " " + t("tf.min");
  if (s < 86400) return Math.floor(s / 3600) + " " + t("tf.hour");
  if (s < 2592000) return Math.floor(s / 86400) + " " + t("tf.day");
  return new Date(tt).toLocaleDateString();
}

function renderSidebar(): void {
  let html = '<div class="tf-feed all' + (current === "latest" ? " sel" : "") + '" data-id="latest">'
    + '<span class="dot"></span><div style="min-width:0;flex:1"><div class="nm">🔥 ' + esc(t("tf.latestAll")) + '</div>'
    + '<div class="meta">' + feeds.length + ' ' + esc(t("tf.trustedFeeds")) + '</div></div></div>';
  html += '<div class="tf-sidehead">' + esc(t("tf.feedsLabel")) + '</div>';
  feeds.forEach((f) => {
    html += '<div class="tf-feed' + (String(current) === String(f.id) ? " sel" : "") + '" data-id="' + f.id + '">'
      + '<span class="dot"></span><div style="min-width:0;flex:1">'
      + '<div class="nm">' + esc(f.name) + '</div>'
      + '<div class="meta">' + esc(f.vendor || host(f.url || "")) + (f.category ? ' · ' + esc(f.category) : '') + '</div></div></div>';
  });
  sideEl().innerHTML = html;
  sideEl().querySelectorAll<HTMLElement>(".tf-feed").forEach((el) => { el.onclick = () => select(el.getAttribute("data-id") || "latest"); });
}

function renderItems(items: Item[], withSource: boolean): void {
  currentItems = items || [];
  if (!items || !items.length) { newsEl().innerHTML = '<div class="tf-status">' + esc(t("tf.noArticles")) + '</div>'; return; }
  newsEl().innerHTML = items.map((it) => {
    const sub: string[] = [];
    if (withSource && it.source) sub.push('<span class="so">' + esc(it.source) + '</span>');
    if (it.date) sub.push(esc(rel(it.date)));
    if (it.link) sub.push(esc(host(it.link)));
    const titleHtml = it.link
      ? '<a class="ttl" href="' + esc(it.link) + '" target="_blank" rel="noopener noreferrer">' + esc(it.title) + '</a>'
      : '<span class="ttl">' + esc(it.title) + '</span>';
    return '<div class="tf-art">' + titleHtml + '<div class="sub">' + sub.join('<span>·</span>') + '</div>'
      + (it.summary ? '<div class="sum">' + esc(it.summary) + '</div>' : '') + '</div>';
  }).join("");
}

function select(id: string): void {
  current = id;
  renderSidebar();
  const titleEl = document.getElementById("tf-title")!;
  const srcEl = document.getElementById("tf-src")!;
  newsEl().innerHTML = '<div class="tf-status">' + esc(t("tf.fetching")) + '</div>';
  if (id === "latest") {
    titleEl.textContent = t("tf.latest");
    fetch("/api/threatfeeds/latest?limit=50").then((r) => r.json()).then((d) => {
      srcEl.textContent = (d.fetched || 0) + "/" + (d.feeds || 0) + " " + t("tf.feedsShort");
      renderItems(d.items, true);
    }).catch((e) => { newsEl().innerHTML = '<div class="tf-status">⚠️ ' + esc(e) + '</div>'; });
  } else {
    const f = feeds.filter((x) => String(x.id) === String(id))[0];
    titleEl.textContent = f ? f.name : t("tf.feed");
    srcEl.innerHTML = f && f.site ? '<a href="' + esc(f.site) + '" target="_blank" rel="noopener noreferrer" style="color:#7c83fd">' + esc(host(f.site)) + ' ↗</a>' : "";
    fetch("/api/threatfeeds/items?id=" + encodeURIComponent(id) + "&limit=25").then((r) =>
      r.ok ? r.json() : r.json().then((j) => { throw new Error(j.error || ("Erreur " + r.status)); })
    ).then((d) => { renderItems(d.items, false); if (d.stale) srcEl.textContent += " " + t("tf.cache"); })
      .catch((e) => { newsEl().innerHTML = '<div class="tf-status">⚠️ ' + esc(e.message || e) + '</div>'; });
  }
}

function mdToHtml(s: string): string {
  return esc(s).replace(/\*\*([^*]+)\*\*/g, '<b style="color:#e2e8f0">$1</b>')
    .replace(/^- (.*)$/gm, '<div style="margin-left:10px">• $1</div>').replace(/\n/g, "<br>");
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n(); applyTranslations();
  document.getElementById("tf-refresh")!.onclick = () => select(current);

  const digestBtn = document.getElementById("tf-digest") as HTMLButtonElement;
  const digestPanel = document.getElementById("tf-digest-panel")!;
  digestBtn.onclick = () => {
    if (!currentItems.length) return;
    digestPanel.style.display = "block";
    digestPanel.innerHTML = "🧠 " + esc(t("tf.generating"));
    digestBtn.disabled = true;
    const payload = { items: currentItems.slice(0, 60).map((i) => ({ title: i.title, summary: i.summary, source: i.source || "", date: i.date })) };
    fetch("/api/ai/feed-digest", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
      .then((r) => r.json().then((d: any) => { if (!r.ok) throw new Error(d.error || ("HTTP " + r.status)); return d; }))
      .then((d: any) => {
        digestPanel.innerHTML = '<div style="font-size:11px;color:#64748b;margin-bottom:6px">🧠 '
          + (d.ai ? t("tf.aiSummary") + " (" + esc(d.model) + ")" : t("tf.offlineSummary") + " " + esc(d.model))
          + " · " + d.items + " " + t("tf.articles") + (d.cves && d.cves.length ? " · " + d.cves.length + " CVE" : "") + "</div>" + mdToHtml(d.digest);
      })
      .catch((e) => { digestPanel.innerHTML = "⚠️ " + esc(e.message || e); })
      .finally(() => { digestBtn.disabled = false; });
  };

  fetch("/api/threatfeeds").then((r) => r.json()).then((list) => {
    feeds = Array.isArray(list) ? list : [];
    renderSidebar(); select("latest");
  }).catch((e) => {
    sideEl().innerHTML = '<div class="tf-status">' + esc(t("tf.loadError")) + '</div>';
    newsEl().innerHTML = '<div class="tf-status">' + esc(e) + '</div>';
  });
});
