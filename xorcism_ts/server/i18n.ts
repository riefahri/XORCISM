/**
 * i18n.ts (server) — Localized messages negotiated via the Accept-Language header
 * (with priority to the `xorcism_lang` cookie set by the client-side selector,
 * to respect the user's explicit choice).
 */

import { Request } from "express";

type Lang = "fr" | "en";

const MESSAGES: Record<string, { fr: string; en: string }> = {
  // Authentication
  "err.tooManyAttempts": {
    fr: "Trop de tentatives. Réessayez plus tard.",
    en: "Too many attempts. Please try again later.",
  },
  "err.badCredentials": {
    fr: "Email ou mot de passe incorrect.",
    en: "Invalid email or password.",
  },
  "err.accountLocked": {
    fr: "Compte verrouillé. Contactez un administrateur.",
    en: "Account locked. Please contact an administrator.",
  },
  "err.notAuthenticated": { fr: "Non authentifié", en: "Not authenticated" },
  "pin.invalid": { fr: "Le PIN doit comporter 4 à 6 chiffres.", en: "The PIN must be 4 to 6 digits." },
  "pin.weak": { fr: "PIN trop simple (chiffres identiques ou suite).", en: "PIN too simple (repeated digits or sequence)." },
  "totp.notEnrolled": { fr: "Aucune application d'authentification n'est en cours d'enregistrement.", en: "No authenticator app enrolment in progress." },
  "totp.badCode": { fr: "Code à 6 chiffres invalide.", en: "Invalid 6-digit code." },
  "register.disabled": { fr: "L'inscription est désactivée.", en: "Self-registration is disabled." },
  "register.badEmail": { fr: "Adresse e-mail invalide.", en: "Invalid email address." },
  "register.exists": { fr: "Un compte existe déjà avec cet e-mail.", en: "An account with this email already exists." },
  "reset.invalid": { fr: "Lien de réinitialisation invalide ou expiré.", en: "Invalid or expired reset link." },
  "err.authRequired": { fr: "Authentification requise", en: "Authentication required" },
  "err.adminOnly": {
    fr: "Accès réservé aux administrateurs",
    en: "Administrator access only",
  },
  "err.sectionDenied": {
    fr: "Accès refusé à cette section.",
    en: "Access denied to this section.",
  },
  "err.accessDenied": {
    fr: "Accès refusé (droits insuffisants).",
    en: "Access denied (insufficient permissions).",
  },
  "err.currentPwWrong": {
    fr: "Mot de passe actuel incorrect.",
    en: "Current password is incorrect.",
  },
  // Password policy
  "pw.tooShort": {
    fr: "Le mot de passe doit comporter au moins 12 caractères.",
    en: "Password must be at least 12 characters long.",
  },
  "pw.tooLong": { fr: "Mot de passe trop long (max 128).", en: "Password too long (max 128)." },
  "pw.classes": {
    fr: "Le mot de passe doit mêler au moins 3 types : minuscules, majuscules, chiffres, symboles.",
    en: "Password must mix at least 3 types: lowercase, uppercase, digits, symbols.",
  },
  "pw.same": {
    fr: "Le nouveau mot de passe doit être différent.",
    en: "The new password must be different.",
  },
  // Admin / validation
  "err.emailInvalid": { fr: "Email invalide.", en: "Invalid email." },
  "err.emailExists": {
    fr: "Un compte avec cet email existe déjà.",
    en: "An account with this email already exists.",
  },
  "err.roleNameRequired": { fr: "Nom de rôle requis.", en: "Role name required." },
  "err.badRequest": { fr: "Requête invalide.", en: "Invalid request." },
  // Pages
  "page.deniedHtml": {
    fr:
      "<h2 style='font-family:sans-serif'>403 — Accès refusé à cette page.</h2>" +
      "<p><a href='/'>Accueil</a> — un administrateur doit vous accorder l'accès.</p>",
    en:
      "<h2 style='font-family:sans-serif'>403 — Access to this page is denied.</h2>" +
      "<p><a href='/'>Home</a> — an administrator must grant you access.</p>",
  },
  "page.adminOnly": {
    fr: "403 — Accès réservé aux administrateurs",
    en: "403 — Administrator access only",
  },
};

export function negotiateLang(req: Request): Lang {
  // 1) Explicit cookie (language selector)
  const raw = req.headers.cookie || "";
  const m = raw.match(/(?:^|;)\s*xorcism_lang=([^;]+)/);
  if (m) {
    const v = decodeURIComponent(m[1]).toLowerCase();
    if (v === "fr" || v === "en") return v;
  }
  // 2) Accept-Language header (browser preference order)
  const al = String(req.headers["accept-language"] || "").toLowerCase();
  for (const part of al.split(",")) {
    const code = part.split(";")[0].trim();
    if (code.startsWith("fr")) return "fr";
    if (code.startsWith("en")) return "en";
  }
  return "fr";
}

/** Translates a key according to the language negotiated for the request. */
export function tr(req: Request, key: string): string {
  const lang = negotiateLang(req);
  const entry = MESSAGES[key];
  if (!entry) return key;
  return entry[lang] ?? entry.fr;
}
