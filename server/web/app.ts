// Hort web app: one console with the views /vault, /devices, /access and
// /r/<id> (contract §5.4, §8.1, §8.2). The vault key lives in this module's
// memory. Tabs and g-chords swap the view without a page load, so an unlocked
// vault stays unlocked. With a lock time other than "immediately", reloads and new tabs
// reopen it until that time (unlock-memory.ts); signing out drops everything.
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
import { forgetDevice, rememberAccount, rememberedAccount } from "./device-memory";
import {
  dropUnlock,
  LOCK_CHOICES,
  LOCK_LABEL,
  LOCK_TTL,
  lockSetting,
  setLockSetting,
  storedUnlock,
  storeUnlock,
  unwrapVaultKey,
  wrapVaultKey,
  type LockAfter,
} from "./unlock-memory";
import { REQUEST_PATH, requestView } from "./request-view";
import { forgetVault, vaultView } from "./vault-view";
import { devicesView } from "./devices-view";

// ---------------------------------------------------------------------------
// State, memory only

type Unlocked = { accountId: Uint8Array; vk: Uint8Array; keys: AccountKeys };
let unlocked: Unlocked | null = null;
let signedIn = false;
// Kit values typed for a kit unlock, kept for printing the kit in the access view.
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
  await keepUnlocked();
}

// ---------------------------------------------------------------------------
// Lock time: the vault stays unlocked across reloads and tabs until then

const UNLOCK_KEY_PATH = "/api/v1/session/unlock-key";

// Wraps the vault key with a fresh unlock key of this session for the chosen
// lock time. Without a session of this account (Emergency Kit alone) the
// server refuses and nothing is kept.
async function keepUnlocked(): Promise<void> {
  const choice = lockSetting();
  const u = unlocked;
  const remembered = rememberedAccount();
  if (!u || choice === "immediately" || !remembered || accountIdEncode(remembered) !== accountIdEncode(u.accountId)) return;
  try {
    const res = await api("PUT", UNLOCK_KEY_PATH, { body: JSON.stringify({ ttl: LOCK_TTL[choice] }) });
    if (!res.ok) {
      dropUnlock();
      return;
    }
    const { key } = (await res.json()) as { key: string };
    const wrapped = await wrapVaultKey(b64Decode(key)!, u.accountId, u.vk);
    // Stored only if nothing changed meanwhile, so a quick switch to "immediately" wins.
    if (unlocked === u && lockSetting() === choice) storeUnlock(wrapped);
  } catch {
    // the vault locks on reload
  }
}

// On page start: reopens the vault this browser keeps unlocked, while the
// server still hands out the session's unlock key. Fetching it counts as use.
async function restoreUnlocked(): Promise<void> {
  const w = storedUnlock();
  if (!w || unlocked) return;
  const accountId = parseAccountId(w.account);
  const remembered = rememberedAccount();
  if (!accountId || !remembered || accountIdEncode(remembered) !== w.account) {
    dropUnlock();
    return;
  }
  let res: Response;
  try {
    res = await fetch(UNLOCK_KEY_PATH, { headers: { "Hort-Account": w.account }, credentials: "same-origin" });
  } catch {
    return; // offline: locked for now, the stored unlock stays
  }
  if (res.status === 401 || res.status === 404 || res.status === 409) dropUnlock();
  if (!res.ok) return;
  try {
    const { key } = (await res.json()) as { key: string };
    const vk = await unwrapVaultKey(b64Decode(key)!, accountId, w);
    const keys = await deriveAccountKeys(vk, accountId);
    unlocked = { accountId, vk, keys };
    signedIn = true;
  } catch {
    dropUnlock();
  }
}

async function changeLock(choice: LockAfter): Promise<void> {
  setLockSetting(choice);
  if (choice !== "immediately") return keepUnlocked();
  dropUnlock();
  await api("DELETE", UNLOCK_KEY_PATH).catch(() => undefined);
}

// Whether an unlock can be kept: a session of the remembered account (an Emergency Kit alone is never kept).
const keepsUnlock = () => {
  const remembered = rememberedAccount();
  return signedIn && !!unlocked && !!remembered && accountIdEncode(remembered) === accountIdEncode(unlocked.accountId);
};

// The server refused the session: the kept unlock is useless from here.
function sessionEnded(): void {
  signedIn = false;
  dropUnlock();
}

// ---------------------------------------------------------------------------
// DOM helpers

type Child = Node | string | null | false | undefined;

function h<K extends keyof HTMLElementTagNameMap>(tag: K, props: Record<string, unknown> = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined) continue;
    if (v === false) {
      // A false flag still applies to a real property (spellcheck: false).
      if (k in el && k !== "class" && !k.startsWith("on")) (el as unknown as Record<string, unknown>)[k] = false;
      continue;
    }
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

function field(label: string, input: HTMLInputElement | HTMLTextAreaElement, hint?: string, cls?: string): HTMLElement {
  input.id ||= `f-${label.toLowerCase().replace(/\W+/g, "-")}`;
  return h("div", { class: cls ? `f ${cls}` : "f" }, h("label", { htmlFor: input.id }, label), input, hint ? h("p", { class: "hint" }, hint) : null);
}

// The status line at the foot of a view; `inline` is a status line inside a block.
function status(inline = false): { el: HTMLElement; set: (text: string, kind?: "error" | "ok") => void } {
  const base = inline ? "status" : "v-status status";
  const el = h("p", { class: base, role: "status", "aria-live": "polite" });
  return {
    el,
    set(text, kind) {
      el.textContent = text;
      el.className = `${base}${kind ? ` status-${kind}` : ""}`;
    },
  };
}

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

// ArrayBuffer.isView instead of instanceof: passkeys from password-manager
// extensions hand over buffers from another realm, where instanceof fails.
const bytes = (b: ArrayBuffer | ArrayBufferView) => (ArrayBuffer.isView(b) ? new Uint8Array(b.buffer, b.byteOffset, b.byteLength) : new Uint8Array(b));
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
// which a discoverable get() only reveals afterwards; when the account is
// neither unlocked in this tab nor remembered by this browser, a second
// prompt evaluates the PRF.
async function passkeySignIn(say: (text: string) => void): Promise<{ result: LoginResult; unlockedNow: boolean }> {
  const options = await ok<{ challenge: string; rpId: string; userVerification: UserVerificationRequirement; timeout: number }>(
    await api("POST", "/api/v1/webauthn/login/options"),
  );
  const known = unlocked?.accountId ?? rememberedAccount();
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
  rememberAccount(result.account_id);
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
  dropUnlock();
  if (rememberedAccount() && confirm("Forget this device? Your next sign-in here then asks for the passkey twice again.")) forgetDevice();
  forget();
  location.assign("/vault");
}

// ---------------------------------------------------------------------------
// Console: one window, a view per address, the session in the menubar

type View = "vault" | "devices" | "access" | "request";
const VIEW_PATH: Record<Exclude<View, "request">, string> = { vault: "/vault", devices: "/devices", access: "/access" };
const CHORD: Record<string, View> = { v: "vault", d: "devices", a: "access", r: "request" };

// The open request keeps its tab until it is answered or declined.
let requestPath: string | null = null;
let help = false;
let kitOpen = false;
// Signed in with a passkey that cannot unlock the vault: the account ID for the kit form.
let signedInLocked: string | null = null;
// The outcome of the previous view for the next view's status line.
let notice: { text: string; kind?: "ok" | "error" } | null = null;
// Starts the passkey sign-in of the unlock view, while it is shown.
let signInNow: (() => void) | null = null;

const viewOf = (path: string): View | null =>
  REQUEST_PATH.test(path) ? "request" : ((Object.keys(VIEW_PATH) as (keyof typeof VIEW_PATH)[]).find((v) => VIEW_PATH[v] === path) ?? null);

const typing = (t: EventTarget | null) => t instanceof HTMLElement && t.matches("input, textarea, select");
// Devices needs only a session, so a user whose passkey cannot unlock the vault can still revoke a lost device.
const sessionOnly = (view: View) => !unlocked && signedIn && view === "devices";

// A document key listener that ends with its view: it detaches on the first key after the view is gone.
function keys(root: HTMLElement, handle: (e: KeyboardEvent) => boolean | void): void {
  const listener = (e: KeyboardEvent) => {
    if (!root.isConnected) return document.removeEventListener("keydown", listener);
    if (e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented) return;
    if (handle(e)) e.preventDefault();
  };
  document.addEventListener("keydown", listener);
}

const promptLine = (cmd: string) => h("div", { class: "prompt static" }, h("span", { class: "ps1" }, "> ", h("span", { class: "cmd" }, cmd)));

function foot(out: ReturnType<typeof status>, hints: string[][]): HTMLElement {
  return h("div", { class: "foot" }, out.el, h("div", { class: "hints", "aria-label": "Keyboard shortcuts" }, ...hints.map(([k, what]) => h("span", {}, h("kbd", {}, k), what))));
}

const NAV_HINTS = [["g v·d·a", "switch"], ["?", "help"]];

// Shows a line in the status bar of the current view.
function flash(text: string, kind?: "ok" | "error"): void {
  const line = document.querySelector<HTMLElement>(".win-body .v-status");
  if (!line) return;
  line.textContent = text;
  line.className = `v-status status${kind ? ` status-${kind}` : ""}`;
}

// --- menubar: account, lock time, sign out

const lockText = (c: LockAfter) => (c === "immediately" ? "when the tab closes" : LOCK_LABEL[c]);

function lockMenu(): HTMLElement {
  const button = h("button", { class: "tlink", type: "button", id: "lock-btn", "aria-haspopup": "menu", "aria-expanded": "false", "aria-controls": "lock-menu" }, `locks ${lockText(lockSetting())}`);
  const items = LOCK_CHOICES.map((c) => h("button", { type: "button", role: "menuitemradio", tabIndex: -1, "aria-checked": String(c === lockSetting()) }, lockText(c)));
  const menu = h("span", { class: "menu", role: "menu", id: "lock-menu", "aria-label": "Lock time", hidden: true }, ...items);
  const wrap = h("span", { class: "lock-wrap" }, button, menu);
  const open = (show: boolean) => {
    menu.hidden = !show;
    button.setAttribute("aria-expanded", String(show));
    if (show) items[LOCK_CHOICES.indexOf(lockSetting())].focus();
  };
  button.addEventListener("click", () => open(button.getAttribute("aria-expanded") !== "true"));
  items.forEach((item, i) =>
    item.addEventListener("click", () => {
      const choice = LOCK_CHOICES[i];
      void changeLock(choice);
      items.forEach((x, j) => x.setAttribute("aria-checked", String(i === j)));
      button.textContent = `locks ${lockText(choice)}`;
      open(false);
      button.focus();
      flash(choice === "immediately" ? "The vault locks when you close or reload this tab." : `The vault locks ${LOCK_LABEL[choice]}.`, "ok");
    }),
  );
  menu.addEventListener("keydown", (e) => {
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "Tab") return open(false);
    if (e.key === "Escape") {
      open(false);
      button.focus();
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") items[(i + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length].focus();
    else return;
    e.preventDefault();
    e.stopPropagation();
  });
  const outside = (e: MouseEvent) => {
    if (!wrap.isConnected) return document.removeEventListener("click", outside);
    if (!menu.hidden && !wrap.contains(e.target as Node)) open(false);
  };
  document.addEventListener("click", outside);
  return wrap;
}

function sessionBar(): void {
  const el = document.getElementById("session");
  if (!el) return;
  const account = unlocked?.accountId ?? rememberedAccount();
  if (!account && !signedIn) {
    const signIn = h("button", { class: "tlink", type: "button" }, "sign in");
    signIn.addEventListener("click", () => {
      kitOpen = false;
      render();
      signInNow?.();
    });
    el.replaceChildren(window.PublicKeyCredential ? signIn : "");
    return;
  }
  const id = account ? accountIdEncode(account) : signedInLocked ?? "";
  const signOutLink = h("button", { class: "tlink", type: "button" }, "sign out");
  signOutLink.addEventListener("click", () => void signOut());
  el.replaceChildren(
    h(
      "span",
      { class: "status-line" },
      h("span", { class: `acct${unlocked ? "" : " locked"}`, title: `Account ID ${id}` }, h("span", { class: "dot", "aria-hidden": "true" }), id.slice(0, 8) + (id.length > 8 ? "…" : "")),
      h("span", { class: "sep", "aria-hidden": "true" }, "·"),
      !unlocked || keepsUnlock() ? lockMenu() : h("span", {}, "locks when the tab closes"),
      h("span", { class: "sep", "aria-hidden": "true" }, "·"),
      signOutLink,
    ),
  );
}

// --- title bar: title and tabs

function windowBar(view: View): void {
  const title = document.querySelector(".win-bar .title");
  const tabs = document.querySelector(".win-bar .tabs");
  if (title) title.textContent = `hort — ${sessionOnly(view) ? view : !unlocked ? (signedIn || rememberedAccount() ? "locked" : "sign in") : help ? "help" : view}`;
  if (!tabs) return;
  const views: View[] = ["vault", "devices", "access"];
  if (requestPath) views.push("request");
  tabs.replaceChildren(
    ...(unlocked
      ? views.map((v) =>
          h(
            "button",
            { class: "tab", role: "tab", type: "button", "aria-selected": String(v === view && !help), onclick: () => go(v) },
            v === "request" ? h("span", { class: "new", "aria-hidden": "true" }) : null,
            v,
            h("kbd", {}, `g ${v[0]}`),
          ),
        )
      : []),
  );
}

function go(view: View): void {
  if (view === "request" && !requestPath) return;
  help = false;
  navigate(view === "request" ? requestPath! : VIEW_PATH[view]);
}

// --- locked or signed out: the console only unlocks

// The passkey button: signs in, unlocks where the passkey can, then `done`.
function passkeyButton(label: string, out: ReturnType<typeof status>, done: () => void): HTMLButtonElement {
  const button = h("button", { class: "tbtn tbtn-primary tbtn-big", type: "button", id: "unlock-btn" }, h("kbd", {}, "⏎"), label);
  action(button, out, async () => {
    if (!window.PublicKeyCredential) throw new Error("This browser does not support passkeys.");
    out.set("Waiting for your passkey …");
    const { result, unlockedNow } = await passkeySignIn((t) => out.set(t));
    if (unlockedNow || unlocked) return done();
    signedInLocked = result.account_id;
    render();
  });
  return button;
}

// Passkey sign-in inside a view whose session the server refused.
function signInBlock(into: HTMLElement, done: () => void, sentence?: string): void {
  const out = status(true);
  into.append(h("section", { class: "block" }, sentence ? h("p", { class: "ink" }, sentence) : null, h("div", { class: "row-actions" }, passkeyButton("sign in with passkey", out, done)), out.el));
}

const REQUEST_SENTENCE = "Your agent asked for a secret. Sign in with your passkey to see the request and answer it.";

function unlockView(body: HTMLElement, view: View): void {
  signInNow = null;
  if (kitOpen || signedInLocked || !window.PublicKeyCredential) return kitView(body, view);
  const known = rememberedAccount();
  const out = status();
  const button = passkeyButton(known ? "unlock with passkey" : "sign in with passkey", out, () => render());
  signInNow = () => button.click();
  const kitButton = h("button", { class: "tbtn", type: "button", onclick: () => openKit(true) }, h("kbd", {}, "k"), "unlock with Emergency Kit");
  const root = h(
    "div",
    { class: "console-view" },
    promptLine(known ? "hort unlock" : "hort sign-in"),
    h(
      "section",
      { class: "block lead" },
      h("p", { class: "ink" }, view === "request" ? REQUEST_SENTENCE : known ? "Your vault is locked. Your passkey unlocks it." : "Sign in with your passkey. It signs you in and unlocks your vault."),
      known
        ? h("p", {}, "Account ", h("code", {}, accountIdEncode(known)), " is remembered in this browser, so one confirmation is enough.")
        : h("p", {}, "The first time on a device you confirm your passkey twice: once to sign in, once to unlock your vault. Hort then remembers your account ID in this browser, so next time one confirmation is enough."),
      h("div", { class: "row-actions" }, button),
      h("p", { class: "alt" }, "No passkey yet, or lost it? ", kitButton),
    ),
    foot(out, [["enter", known ? "unlock" : "sign in"], ["k", "Emergency Kit"]]),
  );
  body.append(root);
  keys(root, (e) => {
    if (typing(e.target) || (e.target as Element).closest("button, a")) return;
    if (e.key === "Enter") button.click();
    else if (e.key === "k") openKit(true);
    else return;
    return true;
  });
}

function openKit(open: boolean): void {
  kitOpen = open;
  if (!open) signedInLocked = null;
  render();
  if (open) [...document.querySelectorAll<HTMLInputElement>(".win-body input")].find((i) => !i.value)?.focus();
}

function kitView(body: HTMLElement, view: View): void {
  const out = status();
  const prefill = signedInLocked ?? (rememberedAccount() ? accountIdEncode(rememberedAccount()!) : "");
  const accountInput = h("input", { autocomplete: "username", spellcheck: false, value: prefill, required: true });
  const keyInput = h("input", { autocomplete: "off", spellcheck: false, required: true, placeholder: "H4-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X" });
  const passInput = h("input", { type: "password", autocomplete: "current-password", required: true });
  const submit = h("button", { class: "tbtn tbtn-primary tbtn-big", type: "submit" }, h("kbd", {}, "⏎"), "unlock");
  const back = window.PublicKeyCredential ? h("button", { class: "tbtn", type: "button", onclick: () => openKit(false) }, h("kbd", {}, "esc"), "back to passkey") : null;
  const form = h(
    "form",
    {},
    h("div", { class: "fgrid" }, field("Account ID", accountInput), field("Secret Key", keyInput), field("Passphrase", passInput)),
    h("div", { class: "row-actions" }, submit, back),
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
      kitOpen = false;
      signedInLocked = null;
      if (view === "request") return render();
      notice = { text: signedIn ? "Unlocked with your Emergency Kit." : "Unlocked with your Emergency Kit. Register a passkey to sign in on this device.", kind: "ok" };
      navigate("/access");
    } catch (err) {
      out.set(messageOf(err), "error");
    } finally {
      submit.disabled = false;
    }
  });
  const root = h(
    "div",
    { class: "console-view" },
    promptLine("hort unlock --kit"),
    signedInLocked
      ? h(
          "section",
          { class: "block" },
          h("h3", {}, "> signed in, vault still locked"),
          h("p", { class: "ink" }, "This passkey signs you in but cannot unlock your vault. Some passkey providers do not support that. Enter your passphrase and Secret Key to unlock."),
        )
      : null,
    h(
      "section",
      { class: "block" },
      h("h3", {}, "> unlock with your Emergency Kit"),
      h("p", {}, window.PublicKeyCredential ? "" : "This browser does not support passkeys. ", "Enter the account ID, Secret Key and passphrase from your Emergency Kit. Enter them only on the server named in your kit."),
      form,
    ),
    foot(out, back ? [["enter", "unlock"], ["esc", "back"]] : [["enter", "unlock"]]),
  );
  body.append(root);
  keys(root, (e) => {
    if (e.key !== "Escape" || !back) return;
    openKit(false);
    return true;
  });
}

// --- access: passkey, new passphrase, Emergency Kit

function accessView(body: HTMLElement, first: typeof notice): void {
  const u = unlocked!;
  const viaKit = kit !== null;
  const out = status();

  const registerButton = h("button", { class: `tbtn tbtn-big${viaKit ? " tbtn-primary" : ""}`, type: "button" }, h("kbd", {}, "p"), viaKit ? "register a passkey" : "add another passkey");
  action(registerButton, out, async () => {
    if (!window.PublicKeyCredential) throw new Error("This browser does not support passkeys.");
    out.set("Waiting for your passkey …");
    const unlocks = await registerPasskey(u, (t) => out.set(t));
    out.set(
      unlocks
        ? "Passkey registered. It signs you in and unlocks your vault."
        : "Passkey registered for sign-in. It cannot unlock your vault, so after signing in you enter your passphrase and Secret Key.",
      "ok",
    );
  });

  const newPass = h("input", { type: "password", autocomplete: "new-password", required: true });
  const repeat = h("input", { type: "password", autocomplete: "new-password", required: true });
  // Unlocked with the kit, the Secret Key is known; unlocked with a passkey, it comes from the printed kit.
  const keyInput = viaKit ? null : h("input", { autocomplete: "off", spellcheck: false, required: true, placeholder: "H4-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X" });
  const passSubmit = h("button", { class: "tbtn tbtn-primary", type: "submit" }, "set new passphrase");
  const passForm = h(
    "form",
    {},
    h(
      "div",
      { class: "fgrid" },
      keyInput &&
        field(
          "Secret Key",
          keyInput,
          "Your passkey opens the vault but never shows your Secret Key, and a new passphrase only works together with it. Copy it from your Emergency Kit. A wrong Secret Key makes the new passphrase useless; your passkeys keep working.",
          "full",
        ),
      field("New passphrase", newPass),
      field("Repeat new passphrase", repeat),
    ),
    h("div", { class: "row-actions" }, passSubmit),
  );
  passForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    passSubmit.disabled = true;
    try {
      if (newPass.value !== repeat.value) throw new Error("The two passphrases differ.");
      const secretKey = await parseSecretKey(kit ? kit.secretKey : keyInput!.value);
      out.set("Setting the new passphrase … this takes a few seconds.");
      const res = await fetch(`/api/v1/accounts/${accountIdEncode(u.accountId)}/slot`);
      const { slot } = await ok<{ slot: WireSlot }>(res);
      const s = await newPassphraseSlot(u.keys, u.vk, secretKey, newPass.value, slot.version);
      const body = JSON.stringify({ version: s.version, bytes: b64Encode(s.bytes), ak_sig: b64Encode(s.akSig) });
      await ok(await api("PUT", `/api/v1/slots/${PASSPHRASE_SLOT}`, { ak: u.keys, body }));
      newPass.value = "";
      repeat.value = "";
      if (keyInput) keyInput.value = "";
      out.set("New passphrase set. Your devices pick it up at their next sync; your Secret Key stays the same.", "ok");
    } catch (err) {
      out.set(messageOf(err), "error");
    } finally {
      passSubmit.disabled = false;
    }
  });

  const print = () => {
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
  };

  const root = h(
    "div",
    { class: "console-view" },
    promptLine("hort access"),
    h(
      "section",
      { class: "block" },
      h("h3", {}, "> passkey"),
      viaKit
        ? h("p", { class: "ink" }, "Your vault is unlocked in this tab with your Emergency Kit. Register a passkey so you can sign in on this device.")
        : h("p", {}, "List and revoke your passkeys under devices (", h("code", {}, "g d"), "). Add another only for a new device or password manager."),
      h("div", { class: "row-actions" }, registerButton),
    ),
    h("section", { class: "block" }, h("h3", {}, "> new passphrase"), passForm),
    h(
      "section",
      { class: "block" },
      h("h3", {}, "> emergency kit"),
      viaKit
        ? h("p", {}, "Print the kit with the values you just entered. Nothing is stored.")
        : h("p", {}, "Your Emergency Kit holds your account ID and Secret Key. You can print it again right after unlocking with it."),
      viaKit && h("div", { class: "row-actions" }, h("button", { class: "tbtn", type: "button", onclick: print }, h("kbd", {}, "k"), "print Emergency Kit")),
    ),
    foot(out, [["p", "add passkey"], ...(viaKit ? [["k", "print kit"]] : []), ...NAV_HINTS]),
  );
  body.append(root);
  if (first) out.set(first.text, first.kind);
  keys(root, (e) => {
    if (typing(e.target)) return;
    if (e.key === "p") registerButton.click();
    else if (e.key === "k" && viaKit) print();
    else return;
    return true;
  });
}

// --- help

function helpView(body: HTMLElement): void {
  const k = (key: string, what: string) => h("li", {}, h("kbd", { class: "k" }, key), h("span", {}, what));
  const out = status();
  body.append(
    h(
      "div",
      { class: "console-view" },
      promptLine("hort help"),
      h(
        "ul",
        { class: "help" },
        h("li", { class: "help-h" }, "// switch view"),
        k("g v", "vault"),
        k("g d", "devices and passkeys"),
        k("g a", "access: passkey, passphrase, Emergency Kit"),
        requestPath ? k("g r", "the open request") : null,
        k("?", "this help"),
        k("esc", "close help"),
        h("li", { class: "help-h" }, "// in a list"),
        k("/", "filter"),
        k("↑ ↓", "select"),
        k("enter", "show or hide value"),
        k("c", "copy, clears after 30 s"),
        k("e", "edit"),
        k("n", "new secret"),
        k("r", "refresh"),
        k("d", "delete value, or revoke a device or passkey"),
        k("y a n", "answer the inline question"),
        h("li", { class: "help-h" }, "// access"),
        k("p", "add a passkey"),
        k("k", "print the Emergency Kit after a kit unlock"),
      ),
      foot(out, [["esc", "close help"]]),
    ),
  );
}

// --- router

function render(path = location.pathname): void {
  const view = viewOf(path) ?? "vault";
  if (view === "request") requestPath = path;
  // A fresh body per view: a view still loading appends to the detached old one, never into the next.
  const old = document.querySelector(".win-body")!;
  const body = old.cloneNode(false) as HTMLElement;
  old.replaceWith(body);
  document.getElementById("kit")?.remove();
  sessionBar();
  windowBar(view);
  document.title = `${sessionOnly(view) ? "Devices" : !unlocked ? "Sign in" : help ? "Help" : view === "request" ? "Secret request" : view[0].toUpperCase() + view.slice(1)} – Hort`;
  const first = notice;
  notice = null;
  let run: void | Promise<void>;
  if (!unlocked && !sessionOnly(view)) run = unlockView(body, view);
  else if (help && unlocked) run = helpView(body);
  else if (view === "access") run = accessView(body, first);
  else if (view === "devices") run = devicesView(body, { h, messageOf, api, ok, login: (into) => (sessionEnded(), signInBlock(into, () => render(), "Sign in with your passkey to see the devices and passkeys of this account.")) });
  else if (view === "request")
    run = requestView(
      body,
      {
        h,
        messageOf,
        api,
        ok,
        keys: () => (unlocked && signedIn ? unlocked.keys : null),
        sessionLost: sessionEnded,
        login: (into, done) => signInBlock(into, done, REQUEST_SENTENCE),
        done: (text, kind) => {
          if (text) {
            requestPath = null;
            notice = { text, kind };
          }
          navigate("/vault");
        },
      },
      path,
    );
  else
    run = vaultView(body, {
      h, messageOf, api, ok,
      unlocked: () => unlocked,
      notice: first ?? undefined,
      // The vault asks for sign-in only when the server refused the session (or there is none).
      login: (into) => {
        sessionEnded();
        signInBlock(into, () => render());
      },
    });
  Promise.resolve(run).catch((err) => body.isConnected && body.append(h("p", { class: "v-status status status-error", role: "status" }, messageOf(err))));
}

function navigate(path: string): void {
  if (path !== location.pathname) history.pushState(null, "", path);
  render(path);
}

// g-chords and help, before any view's own keys: a view sees a key the console took as handled.
let chord: number | undefined;
document.addEventListener("keydown", (e) => {
  if (!unlocked || e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented || typing(e.target)) return;
  if ((e.target as Element).closest?.(".menu, form, .editor")) return;
  if (chord !== undefined) {
    window.clearTimeout(chord);
    chord = undefined;
    flash("");
    const view = CHORD[e.key];
    if (view && (view !== "request" || requestPath)) {
      e.preventDefault();
      go(view);
    }
    return;
  }
  if (e.key === "g") {
    e.preventDefault();
    chord = window.setTimeout(() => {
      chord = undefined;
      flash("");
    }, 1500);
    flash(`g … then v vault · d devices · a access${requestPath ? " · r request" : ""}`);
  } else if (e.key === "?") {
    e.preventDefault();
    help = !help;
    render();
  } else if (e.key === "Escape" && help) {
    e.preventDefault();
    help = false;
    render();
  }
});
window.addEventListener("popstate", () => {
  help = false;
  render();
});
// Wipes memory only; the kept unlock in browser storage is what lets a reload reopen the vault.
window.addEventListener("pagehide", forget);

// Reopens a kept unlock, then renders. "Unlocking …" shows while that runs.
async function start(): Promise<void> {
  // /login and /recover redirect on the server; any other address of this page opens the vault view.
  if (!viewOf(location.pathname)) history.replaceState(null, "", "/vault");
  const path = location.pathname;
  if (storedUnlock()) {
    document.querySelector(".win-body")?.replaceChildren(h("p", { class: "v-status status", role: "status" }, "Unlocking …"));
    await restoreUnlocked();
  }
  // A click during "Unlocking …" rendered its view locked; render it again once unlocked.
  if (location.pathname === path || unlocked) render();
}

// A page restored from the back-forward cache shows the state it had, but its memory was dropped.
window.addEventListener("pageshow", (e) => e.persisted && void start());
void start();
