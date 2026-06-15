/**
 * passkey.ts — WebAuthn ceremonies (passkeys) on the client side.
 * Shared by the login page (login.ts) and the session bar (session-ui.ts).
 */

function b64uToBuf(s: string): ArrayBuffer {
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
function bufToB64u(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function passkeySupported(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;
}

async function postJSON(url: string, body: unknown): Promise<{ ok: boolean; data: Record<string, unknown> }> {
  const res = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, data };
}

/** Registers a new passkey (user already authenticated). */
export async function registerPasskey(name: string): Promise<void> {
  const { ok, data } = await postJSON("/api/auth/passkey/register/options", {});
  if (!ok) throw new Error((data.error as string) || "Échec (options)");
  const o = data.options as Record<string, unknown> & {
    challenge: string; rp: PublicKeyCredentialRpEntity;
    user: { id: string; name: string; displayName: string };
    pubKeyCredParams: PublicKeyCredentialParameters[]; timeout: number;
    attestation: AttestationConveyancePreference; authenticatorSelection: AuthenticatorSelectionCriteria;
    excludeCredentials: { id: string }[];
  };
  const pub: PublicKeyCredentialCreationOptions = {
    challenge: b64uToBuf(o.challenge),
    rp: o.rp,
    user: { id: b64uToBuf(o.user.id), name: o.user.name, displayName: o.user.displayName },
    pubKeyCredParams: o.pubKeyCredParams,
    timeout: o.timeout,
    attestation: o.attestation,
    authenticatorSelection: o.authenticatorSelection,
    excludeCredentials: (o.excludeCredentials || []).map((c) => ({ type: "public-key", id: b64uToBuf(c.id) })),
  };
  const cred = (await navigator.credentials.create({ publicKey: pub })) as PublicKeyCredential | null;
  if (!cred) throw new Error("Annulé");
  const r = cred.response as AuthenticatorAttestationResponse;
  const transports = typeof r.getTransports === "function" ? r.getTransports() : [];
  const v = await postJSON("/api/auth/passkey/register/verify", {
    challengeId: data.challengeId, name,
    credential: {
      id: cred.id,
      response: {
        clientDataJSON: bufToB64u(r.clientDataJSON),
        attestationObject: bufToB64u(r.attestationObject),
        transports,
      },
    },
  });
  if (!v.ok) throw new Error((v.data.error as string) || "Échec de l'enregistrement");
}

/** Login with a passkey. */
export async function loginWithPasskey(email: string): Promise<{ mustChangePassword?: boolean }> {
  const { ok, data } = await postJSON("/api/auth/passkey/login/options", { email });
  if (!ok) throw new Error((data.error as string) || "Échec (options)");
  const o = data.options as {
    challenge: string; rpId: string; timeout: number;
    userVerification: UserVerificationRequirement; allowCredentials: { id: string }[];
  };
  const pub: PublicKeyCredentialRequestOptions = {
    challenge: b64uToBuf(o.challenge),
    rpId: o.rpId, timeout: o.timeout, userVerification: o.userVerification,
    allowCredentials: (o.allowCredentials || []).map((c) => ({ type: "public-key", id: b64uToBuf(c.id) })),
  };
  const cred = (await navigator.credentials.get({ publicKey: pub })) as PublicKeyCredential | null;
  if (!cred) throw new Error("Annulé");
  const r = cred.response as AuthenticatorAssertionResponse;
  const v = await postJSON("/api/auth/passkey/login/verify", {
    challengeId: data.challengeId,
    credential: {
      id: cred.id,
      response: {
        clientDataJSON: bufToB64u(r.clientDataJSON),
        authenticatorData: bufToB64u(r.authenticatorData),
        signature: bufToB64u(r.signature),
        userHandle: r.userHandle ? bufToB64u(r.userHandle) : null,
      },
    },
  });
  if (!v.ok) throw new Error((v.data.error as string) || "Échec de la connexion");
  return v.data as { mustChangePassword?: boolean };
}

export interface PasskeyInfo {
  CredentialID: string; Name: string | null; CreatedDate: string | null; LastUsedDate: string | null;
}
export async function listPasskeys(): Promise<PasskeyInfo[]> {
  const res = await fetch("/api/auth/passkeys");
  if (!res.ok) return [];
  return res.json();
}
export async function deletePasskey(id: string): Promise<boolean> {
  const res = await fetch("/api/auth/passkeys/" + encodeURIComponent(id), { method: "DELETE" });
  return res.ok;
}
