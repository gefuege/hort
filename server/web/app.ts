// Hort web app: /login, /recover, /devices, /vault and /r/<id> (contract §5.4, §8.1, §8.2).
// The vault key lives only in this module's memory. The pages are one
// app: links between them swap the view without a page load, so an unlocked
// vault stays unlocked; closing the tab or signing out drops everything.
// No innerHTML anywhere: the CSP requires Trusted Types for script sinks.
import { b64Decode, b64Encode, b64urlDecode, b64urlEncode, str } from "../src/wire";
import {
  accountIdEncode,
  akHeaders,
  deriveAccountKeys,
  formatSecretKey,
  parseAccountId,
  newPassphraseSlot,
  parseArgonParams,
  parseSecretKey,
  parseSlotBytes,
  passkeyKEKBytes,
  passkeySlot,
  passphraseKEKBytes,
  PASSPHRASE_SLOT,
  prfEvalSalt,
  unwrapSlot,
  verifySlotAuthority,
  wrapSlot,
  type AccountKeys,
  type SlotRecord,
} from "./vault-core";
import { REQUEST_PATH, requestView } from "./request-view";
import { forgetVault, vaultView } from "./vault-view";

// ---------------------------------------------------------------------------
// State, memory only

type Unlocked = { accountId: Uint8Array; vk: Uint8Array; keys: AccountKeys };
let unlocked: Unlocked | null = null;
let signedIn = false;
// Kit values typed on /recover, kept for the print view on that page only.
let kit: { accountId: string; secretKey: string } | null = null;

function forget(): void {
  unlocked?.vk.fill(0);
  unlocked = null;
  kit = null;
  signedIn = false;
  forgetVault();
}

async function unlock(accountId: Uint8Array, vk: Uint8Array, akPub: Uint8Array, slotId: string, slot: SlotRecord): Promise<void> {
  const keys = await deriveAccountKeys(vk, accountId);
  if (!(await verifySlotAuthority(keys, akPub, slotId, slot))) {
    vk.fill(0);
    throw new Error("The server returned a key slot that this account did not sign. Nothing was unlocked.");
  }
  unlocked?.vk.fill(0);
  unlocked = { accountId, vk, keys };
}

// ---------------------------------------------------------------------------
// DOM helpers

type Child = Node | string | null | false | undefined;

function h<K extends keyof HTMLElementTagNameMap>(tag: K, props: Record<string, unknown> = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === false) continue;
    if (k === "class") el.className = String(v);
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v as EventListener);
    else if (k in el && !k.includes("-")) (el as unknown as Record<string, unknown>)[k] = v;
    else el.setAttribute(k, String(v));
  }
  add(el, ...children);
  return el;
}

function add(el: HTMLElement, ...children: Child[]): void {
  for (const c of children) if (c !== null && c !== false && c !== undefined) el.append(c);
}

function field(label: string, input: HTMLInputElement | HTMLTextAreaElement, hint?: string): HTMLElement {
  input.id ||= `f-${label.toLowerCase().replace(/\W+/g, "-")}`;
  return h("div", { class: "field" }, h("label", { htmlFor: input.id }, label), input, hint ? h("p", { class: "hint" }, hint) : null);
}

function status(): { el: HTMLElement; set: (text: string, kind?: "error" | "ok") => void } {
  const el = h("p", { class: "status", role: "status" });
  return {
    el,
    set(text, kind) {
      el.textContent = text;
      el.className = `status${kind ? ` status-${kind}` : ""}`;
    },
  };
}

const time = (t: number | null) => (t === null ? "never" : new Date(t * 1000).toLocaleString());

// Runs a button action with the button disabled and errors shown in place.
function action(button: HTMLButtonElement, out: ReturnType<typeof status>, run: () => Promise<void>): void {
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await run();
    } catch (err) {
      out.set(messageOf(err), "error");
    } finally {
      button.disabled = false;
    }
  });
}

function messageOf(err: unknown): string {
  if (err instanceof DOMException && err.name === "NotAllowedError") return "The passkey prompt was cancelled or timed out.";
  if (err instanceof DOMException && err.name === "InvalidStateError") return "This passkey is already registered for this account.";
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// API

async function api(method: string, path: string, o: { body?: string; ak?: AccountKeys } = {}): Promise<Response> {
  const body = o.body ?? "";
  const headers: Record<string, string> = o.ak ? await akHeaders(o.ak, method, path, str(body)) : {};
  // A session call names the unlocked account, so the server refuses a session of another account (409).
  if (!o.ak && unlocked) headers["Hort-Account"] = accountIdEncode(unlocked.accountId);
  if (method !== "GET") headers["Hort-CSRF"] = "1";
  if (o.body !== undefined) headers["Content-Type"] = "application/json";
  return fetch(path, { method, headers, body: method === "GET" ? undefined : body, credentials: "same-origin" });
}

async function ok<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error((await res.text()).trim() || `request failed (${res.status})`);
  return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
}

type WireSlot = { version: number; bytes: string; ak_sig: string };
const slotRecord = (s: WireSlot): SlotRecord => ({ version: s.version, bytes: b64Decode(s.bytes)!, akSig: b64Decode(s.ak_sig)! });

// ---------------------------------------------------------------------------
// WebAuthn

const bytes = (b: ArrayBuffer | ArrayBufferView) => (b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer, b.byteOffset, b.byteLength));
type PRFOutputs = { enabled?: boolean; results?: { first?: ArrayBuffer | ArrayBufferView } };
const prfOf = (cred: PublicKeyCredential) => (cred.getClientExtensionResults() as { prf?: PRFOutputs }).prf;
const prfInput = async (accountId: Uint8Array) => ({ prf: { eval: { first: await prfEvalSalt(accountId) } } }) as AuthenticationExtensionsClientInputs;

// PRF output of one credential, from a get() whose challenge nobody verifies:
// it only evaluates the PRF.
async function evaluatePRF(credentialId: Uint8Array, accountId: Uint8Array): Promise<Uint8Array | null> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)) as BufferSource,
      allowCredentials: [{ type: "public-key", id: credentialId as BufferSource }],
      userVerification: "required",
      extensions: await prfInput(accountId),
    },
  })) as PublicKeyCredential | null;
  const first = cred && prfOf(cred)?.results?.first;
  return first ? bytes(first) : null;
}

type RegisterOptions = {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  authenticatorSelection: AuthenticatorSelectionCriteria;
  attestation: AttestationConveyancePreference;
  excludeCredentials: { type: "public-key"; id: string }[];
  timeout: number;
};

// Registers a passkey for the unlocked account. Returns whether it got a
// slot, that is whether it can unlock the vault.
async function registerPasskey(u: Unlocked, say: (text: string) => void): Promise<boolean> {
  const options = await ok<RegisterOptions>(await api("POST", "/api/v1/webauthn/register/options", { ak: u.keys }));
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: b64urlDecode(options.challenge)! as BufferSource,
      rp: options.rp,
      user: { ...options.user, id: b64urlDecode(options.user.id)! as BufferSource },
      pubKeyCredParams: options.pubKeyCredParams,
      authenticatorSelection: options.authenticatorSelection,
      attestation: options.attestation,
      excludeCredentials: options.excludeCredentials.map((c) => ({ type: c.type, id: b64urlDecode(c.id)! as BufferSource })),
      timeout: options.timeout,
      extensions: await prfInput(u.accountId),
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was created.");
  const rawId = bytes(cred.rawId);
  const prf = prfOf(cred);
  let output = prf?.results?.first ? bytes(prf.results.first) : null;
  if (!output && prf?.enabled) {
    say("Confirm the passkey once more so it can unlock your vault.");
    output = await evaluatePRF(rawId, u.accountId);
  }
  let slot: WireSlot | null = null;
  if (output) {
    const { id, params } = await passkeySlot(rawId);
    const kek = await passkeyKEKBytes(output, u.accountId);
    const s = await wrapSlot(kek, u.vk, u.keys, id, 1, params);
    kek.fill(0);
    slot = { version: s.version, bytes: b64Encode(s.bytes), ak_sig: b64Encode(s.akSig) };
  }
  const att = cred.response as AuthenticatorAttestationResponse;
  const response = {
    id: cred.id,
    rawId: b64urlEncode(rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64urlEncode(bytes(att.clientDataJSON)),
      attestationObject: b64urlEncode(bytes(att.attestationObject)),
      transports: att.getTransports?.() ?? [],
    },
    clientExtensionResults: {}, // the PRF output never leaves the browser
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
  };
  await ok(await api("POST", "/api/v1/webauthn/register/verify", { ak: u.keys, body: JSON.stringify({ response, slot }) }));
  return slot !== null;
}

type LoginResult = { account_id: string; ak_pub: string; credential_id: string; slot: (WireSlot & { id: string }) | null };

// Discoverable passkey sign-in. The PRF eval salt depends on the account ID,
// which a discoverable get() only reveals afterwards; when the account is not
// known in this tab yet, a second prompt evaluates the PRF.
async function passkeySignIn(say: (text: string) => void): Promise<{ result: LoginResult; unlockedNow: boolean }> {
  const options = await ok<{ challenge: string; rpId: string; userVerification: UserVerificationRequirement; timeout: number }>(
    await api("POST", "/api/v1/webauthn/login/options"),
  );
  const known = unlocked?.accountId ?? null;
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: b64urlDecode(options.challenge)! as BufferSource,
      rpId: options.rpId,
      userVerification: options.userVerification,
      timeout: options.timeout,
      extensions: known ? await prfInput(known) : undefined,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was selected.");
  const a = cred.response as AuthenticatorAssertionResponse;
  const response = {
    id: cred.id,
    rawId: b64urlEncode(bytes(cred.rawId)),
    type: cred.type,
    response: {
      clientDataJSON: b64urlEncode(bytes(a.clientDataJSON)),
      authenticatorData: b64urlEncode(bytes(a.authenticatorData)),
      signature: b64urlEncode(bytes(a.signature)),
      userHandle: a.userHandle ? b64urlEncode(bytes(a.userHandle)) : null,
    },
    clientExtensionResults: {},
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
  };
  const result = await ok<LoginResult>(await api("POST", "/api/v1/webauthn/login/verify", { body: JSON.stringify(response) }));
  signedIn = true;
  if (!result.slot) return { result, unlockedNow: false };
  const accountId = parseAccountId(result.account_id)!;
  const first = known && accountIdEncode(known) === result.account_id ? prfOf(cred)?.results?.first : undefined;
  let prf = first ? bytes(first) : null;
  if (!prf) {
    say("Signed in. Confirm the passkey once more to unlock your vault.");
    prf = await evaluatePRF(bytes(cred.rawId), accountId);
  }
  if (!prf) return { result, unlockedNow: false };
  const record = slotRecord(result.slot);
  const parsed = parseSlotBytes(record.bytes);
  if (!parsed) throw new Error("The passkey key slot is malformed.");
  const kek = await passkeyKEKBytes(prf, accountId);
  const vk = await unwrapSlot(kek, accountId, result.slot.id, record.version, parsed);
  kek.fill(0);
  await unlock(accountId, vk, b64Decode(result.ak_pub)!, result.slot.id, record);
  return { result, unlockedNow: true };
}

// Unlock with passphrase and Secret Key against the passphrase slot (2SKD).
async function kitUnlock(accountId: Uint8Array, secretKey: Uint8Array, passphrase: string): Promise<number> {
  const res = await fetch(`/api/v1/accounts/${accountIdEncode(accountId)}/slot`);
  if (res.status === 404) throw new Error("There is no account with this ID on this server.");
  const { ak_pub, slot } = await ok<{ ak_pub: string; slot: WireSlot & { id: string } }>(res);
  const record = slotRecord(slot);
  const parsed = parseSlotBytes(record.bytes);
  const argon = parsed && parseArgonParams(parsed.params);
  if (!parsed || !argon) throw new Error("The passphrase slot of this account is malformed.");
  const kek = await passphraseKEKBytes(passphrase, secretKey, accountId, argon.salt, argon.argon);
  let vk: Uint8Array;
  try {
    vk = await unwrapSlot(kek, accountId, PASSPHRASE_SLOT, record.version, parsed);
  } catch {
    throw new Error("The passphrase and Secret Key do not unlock this account.");
  } finally {
    kek.fill(0);
  }
  await unlock(accountId, vk, b64Decode(ak_pub)!, PASSPHRASE_SLOT, record);
  return record.version;
}

async function signOut(): Promise<void> {
  await api("DELETE", "/api/v1/session").catch(() => undefined);
  forget();
  location.assign("/login");
}

// ---------------------------------------------------------------------------
// Views

function kitForm(onUnlocked: () => void, accountIdPrefill = ""): HTMLElement {
  const out = status();
  const accountInput = h("input", { autocomplete: "username", spellcheck: false, value: accountIdPrefill, required: true });
  const keyInput = h("input", { autocomplete: "off", spellcheck: false, required: true, placeholder: "H4-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X" });
  const passInput = h("input", { type: "password", autocomplete: "current-password", required: true });
  const submit = h("button", { class: "btn btn-primary", type: "submit" }, "Unlock");
  const form = h(
    "form",
    { class: "form" },
    field("Account ID", accountInput),
    field("Secret Key", keyInput),
    field("Passphrase", passInput),
    h("div", { class: "actions" }, submit),
    out.el,
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    submit.disabled = true;
    try {
      const accountId = parseAccountId(accountInput.value);
      if (!accountId) throw new Error("Account ID mistyped");
      const secretKey = await parseSecretKey(keyInput.value);
      out.set("Unlocking … this takes a few seconds.");
      await kitUnlock(accountId, secretKey, passInput.value);
      kit = { accountId: accountIdEncode(accountId), secretKey: await formatSecretKey(secretKey) };
      passInput.value = "";
      keyInput.value = "";
      onUnlocked();
    } catch (err) {
      out.set(messageOf(err), "error");
    } finally {
      submit.disabled = false;
    }
  });
  return form;
}

function unlockedPanel(): HTMLElement {
  const out = status();
  const signOutButton = h("button", { class: "btn btn-ghost", type: "button" }, "Sign out");
  action(signOutButton, out, signOut);
  return h(
    "section",
    { class: "panel" },
    h("h2", { class: "panel-h" }, "Vault unlocked"),
    h("p", {}, "Account ", h("code", {}, accountIdEncode(unlocked!.accountId))),
    h("p", { class: "muted" }, "Your vault key stays in this tab only. Closing the tab or signing out locks it again."),
    h("div", { class: "actions" }, signedIn ? h("a", { class: "btn btn-primary", href: "/vault" }, "Open vault") : null, signedIn ? h("a", { class: "btn btn-ghost", href: "/devices" }, "Devices") : null, location.pathname === "/recover" ? null : h("a", { class: "btn btn-ghost", href: "/recover" }, "Set new passphrase"), signOutButton),
    out.el,
  );
}

function loginView(main: HTMLElement, onUnlocked: () => void = () => render("/login")): void {
  if (unlocked && signedIn) {
    main.append(unlockedPanel());
    return;
  }
  if (!window.PublicKeyCredential) {
    main.append(
      h("p", { class: "sec-intro" }, "This browser does not support passkeys. ", h("a", { href: "/recover" }, "Unlock with your Emergency Kit"), " instead."),
    );
    return;
  }
  const out = status();
  const button = h("button", { class: "btn btn-primary", type: "button" }, "Sign in with a passkey");
  const area = h("div", {});
  action(button, out, async () => {
    out.set("Waiting for your passkey …");
    const { result, unlockedNow } = await passkeySignIn((t) => out.set(t));
    if (unlockedNow) {
      onUnlocked();
      return;
    }
    button.hidden = true;
    out.set("");
    area.replaceChildren(
      h(
        "section",
        { class: "panel" },
        h("h2", { class: "panel-h" }, "Signed in, vault still locked"),
        h("p", {}, "This passkey signs you in but cannot unlock your vault. Some passkey providers do not support that. Enter your passphrase and Secret Key to unlock."),
        kitForm(onUnlocked, result.account_id),
      ),
    );
  });
  main.append(
    h("p", { class: "sec-intro" }, "Sign in with a passkey you registered for Hort. A passkey that supports it also unlocks your vault."),
    h("div", { class: "actions" }, button),
    out.el,
    area,
    h("p", { class: "muted" }, "No passkey yet, or lost it? ", h("a", { href: "/recover" }, "Recover with your Emergency Kit"), "."),
  );
}

function recoverView(main: HTMLElement): void {
  if (!unlocked) {
    main.append(
      h(
        "p",
        { class: "sec-intro" },
        "Enter the account ID, Secret Key and passphrase from your Emergency Kit. Enter them only on the server named in your kit.",
      ),
      kitForm(() => render("/recover")),
    );
    return;
  }
  const u = unlocked;

  const passkeyOut = status();
  const registerButton = h("button", { class: "btn btn-primary", type: "button" }, "Register a passkey");
  const next = h("div", { class: "actions" });
  action(registerButton, passkeyOut, async () => {
    if (!window.PublicKeyCredential) throw new Error("This browser does not support passkeys.");
    passkeyOut.set("Waiting for your passkey …");
    const unlocks = await registerPasskey(u, (t) => passkeyOut.set(t));
    passkeyOut.set(
      unlocks
        ? "Passkey registered. It signs you in and unlocks your vault."
        : "Passkey registered for sign-in. It cannot unlock your vault, so after signing in you enter your passphrase and Secret Key.",
      "ok",
    );
    next.replaceChildren(h("a", { class: "btn btn-ghost", href: "/login" }, "Sign in with it"));
  });

  const passOut = status();
  const newPass = h("input", { type: "password", autocomplete: "new-password", required: true });
  const repeat = h("input", { type: "password", autocomplete: "new-password", required: true });
  // Unlocked with the kit, the Secret Key is known; unlocked with a passkey, it comes from the printed kit.
  const keyInput = kit ? null : h("input", { autocomplete: "off", spellcheck: false, required: true, placeholder: "H4-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X" });
  const passSubmit = h("button", { class: "btn btn-ghost", type: "submit" }, "Set new passphrase");
  const passForm = h(
    "form",
    { class: "form" },
    keyInput && field("Secret Key", keyInput, "From your Emergency Kit. A Secret Key that is not yours makes the new passphrase useless, and your passkeys stay the way in."),
    field("New passphrase", newPass),
    field("Repeat new passphrase", repeat),
    h("div", { class: "actions" }, passSubmit),
    passOut.el,
  );
  passForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    passSubmit.disabled = true;
    try {
      if (newPass.value !== repeat.value) throw new Error("The two passphrases differ.");
      const secretKey = await parseSecretKey(kit ? kit.secretKey : keyInput!.value);
      passOut.set("Setting the new passphrase … this takes a few seconds.");
      const res = await fetch(`/api/v1/accounts/${accountIdEncode(u.accountId)}/slot`);
      const { slot } = await ok<{ slot: WireSlot }>(res);
      const s = await newPassphraseSlot(u.keys, u.vk, secretKey, newPass.value, slot.version);
      const body = JSON.stringify({ version: s.version, bytes: b64Encode(s.bytes), ak_sig: b64Encode(s.akSig) });
      await ok(await api("PUT", `/api/v1/slots/${PASSPHRASE_SLOT}`, { ak: u.keys, body }));
      newPass.value = "";
      repeat.value = "";
      if (keyInput) keyInput.value = "";
      passOut.set("New passphrase set. Your devices pick it up at their next sync; your Secret Key stays the same.", "ok");
    } catch (err) {
      passOut.set(messageOf(err), "error");
    } finally {
      passSubmit.disabled = false;
    }
  });

  const printButton = h("button", { class: "btn btn-ghost", type: "button" }, "Print Emergency Kit");
  printButton.addEventListener("click", () => {
    if (!kit) return;
    document.getElementById("kit")?.remove();
    document.body.append(
      h(
        "section",
        { id: "kit", class: "kit" },
        h("h2", {}, "Hort Emergency Kit"),
        h("p", {}, "This kit restores access to your Hort vault when you have no unlocked device. Keep it somewhere safe and offline; together with your passphrase it opens your vault."),
        h("dl", {}, h("dt", {}, "Server"), h("dd", {}, location.origin), h("dt", {}, "Account ID"), h("dd", {}, kit.accountId), h("dt", {}, "Secret Key"), h("dd", {}, kit.secretKey), h("dt", {}, "Passphrase"), h("dd", {}, "______________________________")),
      ),
    );
    window.print();
  });

  add(main,
    h("p", { class: "sec-intro" }, "Your vault is unlocked in this tab. Register a passkey so you can sign in on this device, or set a new passphrase."),
    h("section", { class: "panel" }, h("h2", { class: "panel-h" }, "Passkey"), h("div", { class: "actions" }, registerButton), passkeyOut.el, next),
    h("section", { class: "panel" }, h("h2", { class: "panel-h" }, "New passphrase"), passForm),
    kit ? h("section", { class: "panel" }, h("h2", { class: "panel-h" }, "Emergency Kit"), h("p", { class: "muted" }, "Print the kit with the values you just entered. Nothing is stored."), h("div", { class: "actions" }, printButton)) : null,
    unlockedPanel(),
  );
}

type Listing = {
  devices: { id: string; name: string; created_at: number; last_seen_at: number | null; revoked_at: number | null }[];
  passkeys: { id: string; prf: boolean; created_at: number; last_used_at: number | null; revoked_at: number | null }[];
  last_visit_at?: number | null;
};

async function devicesView(main: HTMLElement): Promise<void> {
  const out = status();
  main.append(out.el);
  const res = await fetch("/api/v1/devices", { credentials: "same-origin" });
  if (res.status === 401) {
    signedIn = false;
    out.set("");
    main.append(h("p", { class: "sec-intro" }, "Sign in with your passkey to see your devices and passkeys."), h("div", { class: "actions" }, h("a", { class: "btn btn-primary", href: "/login" }, "Sign in")));
    return;
  }
  const list = await ok<Listing>(res);
  signedIn = true;

  const since = list.last_visit_at ?? null;
  const notices: string[] = [];
  if (since !== null) {
    for (const d of list.devices) {
      if (d.created_at > since) notices.push(`New device “${d.name}” enrolled ${time(d.created_at)}`);
      if (d.revoked_at !== null && d.revoked_at > since) notices.push(`Device “${d.name}” revoked ${time(d.revoked_at)}`);
    }
    for (const p of list.passkeys) {
      if (p.created_at > since) notices.push(`New passkey ${p.id.slice(0, 8)} added ${time(p.created_at)}`);
      if (p.revoked_at !== null && p.revoked_at > since) notices.push(`Passkey ${p.id.slice(0, 8)} revoked ${time(p.revoked_at)}`);
    }
  }

  // Marks the row revoked in place: a reload would reset the server-side visit time and drop the notices above.
  const revoke = (label: string, item: { id: string; revoked_at: number | null }) => {
    const b = h("button", { class: "btn btn-ghost btn-small", type: "button" }, "Revoke");
    action(b, out, async () => {
      if (!confirm(`Revoke ${label}? It loses access to this account's server.`)) return;
      await ok(await api("DELETE", `/api/v1/devices/${item.id}`));
      item.revoked_at = Math.floor(Date.now() / 1000);
      b.replaceWith(state(item.revoked_at, b));
    });
    return b;
  };
  const state = (revoked: number | null, b: HTMLElement) => (revoked === null ? b : h("span", { class: "muted" }, `revoked ${time(revoked)}`));

  const signOutButton = h("button", { class: "btn btn-ghost", type: "button" }, "Sign out");
  action(signOutButton, out, signOut);

  add(main,
    notices.length
      ? h("section", { class: "notices", "aria-label": "Since your last visit" }, h("h2", { class: "panel-h" }, "Since your last visit"), h("ul", {}, ...notices.map((n) => h("li", {}, n))))
      : null,
    h("h2", { class: "sub-h" }, "Devices"),
    h(
      "table",
      { class: "list" },
      h("thead", {}, h("tr", {}, h("th", {}, "Name"), h("th", {}, "Added"), h("th", {}, "Last seen"), h("th", {}, ""))),
      h("tbody", {}, ...list.devices.map((d) => h("tr", {}, h("td", {}, d.name), h("td", { "data-label": "Added" }, time(d.created_at)), h("td", { "data-label": "Last seen" }, time(d.last_seen_at)), h("td", {}, state(d.revoked_at, revoke(`device “${d.name}”`, d)))))),
    ),
    h("h2", { class: "sub-h" }, "Passkeys"),
    list.passkeys.length
      ? h(
          "table",
          { class: "list" },
          h("thead", {}, h("tr", {}, h("th", {}, "Passkey"), h("th", {}, "Unlocks vault"), h("th", {}, "Added"), h("th", {}, "Last used"), h("th", {}, ""))),
          h("tbody", {}, ...list.passkeys.map((p) => h("tr", {}, h("td", {}, h("code", {}, p.id.slice(0, 8))), h("td", { "data-label": "Unlocks vault" }, p.prf ? "yes" : "no"), h("td", { "data-label": "Added" }, time(p.created_at)), h("td", { "data-label": "Last used" }, time(p.last_used_at)), h("td", {}, state(p.revoked_at, revoke(`passkey ${p.id.slice(0, 8)}`, p)))))),
        )
      : h("p", { class: "muted" }, "No passkeys. ", h("a", { href: "/recover" }, "Register one"), " after unlocking with your Emergency Kit."),
    h(
      "p",
      { class: "aside-note" },
      "Revoking ends server access for that device or passkey. It does not protect against anyone who already holds your vault key; in that case create a new account and change the exposed secrets where they were issued.",
    ),
    h("div", { class: "actions" }, signOutButton),
  );
}

// ---------------------------------------------------------------------------
// Router

const routes: Record<string, { tag: string; title: string; view: (main: HTMLElement) => void | Promise<void> }> = {
  "/login": { tag: "// login", title: "Sign in", view: loginView },
  "/recover": { tag: "// recover", title: "Recover access", view: recoverView },
  "/devices": { tag: "// devices", title: "Devices", view: devicesView },
  "/vault": { tag: "// vault", title: "Vault", view: (main) => vaultView(main, { h, field, status, action, messageOf, api, ok, unlocked: () => unlocked }) },
};

// /r/<id>: an agent's secret request (contract §7.3).
const requestRoute = {
  tag: "// request",
  title: "Secret request",
  view: (main: HTMLElement) =>
    requestView(
      main,
      {
        h,
        status,
        messageOf,
        api,
        ok,
        keys: () => (unlocked && signedIn ? unlocked.keys : null),
        sessionLost: () => {
          signedIn = false;
        },
        login: (into, done) => loginView(into, done),
      },
      location.pathname,
    ),
};

const routeFor = (path: string) => routes[path] ?? (REQUEST_PATH.test(path) ? requestRoute : undefined);

function render(path: string): void {
  const route = routeFor(path)!;
  const main = document.querySelector("main")!;
  document.getElementById("kit")?.remove();
  document.title = `${route.title} – Hort`;
  for (const a of document.querySelectorAll<HTMLAnchorElement>(".m-links a")) {
    if (a.pathname === path) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  main.replaceChildren(h("p", { class: "sec-tag" }, route.tag), h("h1", { class: "sec-h" }, route.title));
  Promise.resolve(route.view(main)).catch((err) => main.append(h("p", { class: "status status-error", role: "status" }, messageOf(err))));
}

document.addEventListener("click", (e) => {
  const a = (e.target as Element).closest?.("a");
  if (!a || a.origin !== location.origin || !routeFor(a.pathname) || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  e.preventDefault();
  if (a.pathname !== location.pathname) history.pushState(null, "", a.pathname);
  render(a.pathname);
});
window.addEventListener("popstate", () => routeFor(location.pathname) && render(location.pathname));
window.addEventListener("pagehide", forget);
// A page restored from the back-forward cache shows the state it had, but its memory was dropped.
window.addEventListener("pageshow", (e) => e.persisted && routeFor(location.pathname) && render(location.pathname));
if (routeFor(location.pathname)) render(location.pathname);
