// /vault (contract §8.1, §8.2): the vault view of the console, for the unlocked vault in this tab. The first
// visit pulls every revision from cursor 0, later visits in the same tab pull
// deltas. Revisions are decrypted and reduced in memory only. Every write goes
// through validateWrite and the Append rule against the in-memory entry, then
// POST /revisions. Values reach the DOM only once an entry's editor or "Show" is
// opened; the editor grid keeps them masked until "Show values".
import { b64Decode, b64Encode, b64urlDecode, b64urlEncode } from "../src/wire";
import { formatTime } from "./format-time";
import { notALogin } from "./not-a-login";
import { accountIdEncode, appendStamp, current, entries, entryOf, foldKey, lookupKey, newId, nowNs, openRevision, resolve, sealRevision, spelling, validateWrite, type AccountKeys, type Current, type Op, type Revision } from "./vault-core";
import {
  deriveShareKeys,
  formatShareLink,
  normalizeShareName,
  openShareAnswer,
  openShareMeta,
  sealShare,
  sealShareMeta,
  SHARE_LINK_KEY_BYTES,
  type SharedAnswer,
  type SharedField,
  type SharedSecret,
  type ShareKind,
} from "./share-core";

type Child = Node | string | null | false | undefined;
export type Unlocked = { accountId: Uint8Array; keys: AccountKeys };
type Api = Pick<Host, "api" | "ok">;

// What the page needs from the app shell, which owns the unlocked vault.
export type Host = {
  h: <K extends keyof HTMLElementTagNameMap>(tag: K, props?: Record<string, unknown>, ...children: Child[]) => HTMLElementTagNameMap[K];
  messageOf: (err: unknown) => string;
  // Session calls carry Hort-Account of the unlocked vault; the server answers
  // 409 when the session belongs to another account.
  api: (method: string, path: string, o?: { body?: string }) => Promise<Response>;
  ok: <T>(res: Response) => Promise<T>;
  unlocked: () => Unlocked | null;
  // Renders passkey sign-in (and unlock) into `into`; the vault opens once it is unlocked.
  login: (into: HTMLElement) => void;
  // A line for the status bar once the vault is loaded, such as the outcome of a request.
  notice?: { text: string; kind?: "ok" | "error" };
};

type Vault = { account: string; cursor: number; entries: Map<string, Revision[]>; ids: Set<string>; skipped: number };
let vault: Vault | null = null;

export function forgetVault(): void {
  vault = null;
}

// The server refused the session: missing or expired (401), or signed in to
// another account than the vault unlocked in this tab (409).
export class SignInRequired extends Error {}

function sessionRefused(res: Response): SignInRequired | null {
  if (res.status === 401) return new SignInRequired("Your session ended. Your passkey signs you in and unlocks your vault.");
  if (res.status === 409) {
    return new SignInRequired("You are signed in to a different account than the vault unlocked in this tab. Sign in with a passkey of this account, or use its Emergency Kit.");
  }
  return null;
}

type Page = { revisions: { seq: number; id: string; ct: string }[]; cursor: number; more: boolean };

function remember(v: Vault, name: string, r: Revision): void {
  if (v.ids.has(r.id)) return;
  v.ids.add(r.id);
  const list = v.entries.get(name);
  if (list) list.push(r);
  else v.entries.set(name, [r]);
}

// Pulls everything after the cursor and merges by revision ID. A revision
// that does not decrypt or decode is skipped and counted (§3.4).
export async function pull(host: Api, u: Unlocked): Promise<Vault> {
  const account = accountIdEncode(u.accountId);
  if (vault?.account !== account) vault = { account, cursor: 0, entries: new Map(), ids: new Set(), skipped: 0 };
  const v = vault;
  for (;;) {
    const res = await host.api("GET", `/api/v1/revisions?after=${v.cursor}`);
    const refused = sessionRefused(res);
    if (refused) throw refused;
    const page = await host.ok<Page>(res);
    for (const { id, ct } of page.revisions) {
      if (v.ids.has(id)) continue;
      try {
        const { name, revision } = await openRevision(u.keys, id, b64Decode(ct) ?? new Uint8Array());
        remember(v, name, revision);
      } catch {
        // The error may quote decrypted bytes, so only the ID is logged.
        v.skipped++;
        console.warn(`skipped revision ${id}: it does not decrypt or decode`);
      }
    }
    v.cursor = page.cursor;
    if (!page.more) return v;
  }
}

export type Change = { op: Op; field: string; key: string; value: string };

// Pulls deltas first, so the Append rule sees writes from other devices,
// then stamps, validates, seals and pushes the changes as one batch. Changes
// land on the entry `name` folds to, in the spelling it already holds; the
// result names that entry and the revisions as written.
export async function write(host: Api, u: Unlocked, typed: string, changes: Change[]): Promise<{ name: string; written: Revision[] }> {
  const v = await pull(host, u);
  const { name, revisions: entry } = entryOf(v.entries, typed);
  const known = [...entry];
  const built: Revision[] = [];
  for (const c of changes) {
    const r: Revision = { id: newId(), recordedAt: appendStamp(known, nowNs()), ...c, ...spelling(known, c.field, c.key) };
    const problem = validateWrite(name, r);
    if (problem) throw new Error(problem);
    known.push(r);
    built.push(r);
  }
  const revisions = await Promise.all(built.map(async (r) => ({ id: r.id, ct: b64Encode(await sealRevision(u.keys, name, r)) })));
  const res = await host.api("POST", "/api/v1/revisions", { body: JSON.stringify({ revisions }) });
  const refused = sessionRefused(res);
  if (refused) throw refused;
  const result = await host.ok<{ accepted: string[]; duplicate: string[] }>(res);
  const stored = new Set([...result.accepted, ...result.duplicate]);
  for (const r of built) if (stored.has(r.id)) remember(v, name, r);
  return { name, written: built };
}

// ---------------------------------------------------------------------------
// Shares: a snapshot of one secret for one recipient, opened by link (share-core.ts).
// A request is a share the recipient answers once; the owner reviews the answer.

export type Expiry = 3600 | 86400 | 604800;
const EXPIRY_LABEL: Record<Expiry, string> = { 3600: "1 hour", 86400: "1 day", 604800: "7 days" };

// What a share of the secret carries for the row's env and context: each field
// with the value it resolves to there (hort get NAME FIELD --env E --context C).
export function shareFields(revisions: Revision[], env: string, context: string): SharedField[] {
  const fields = [...new Set([...current(revisions).values.values()].map((x) => x.field))].sort(order);
  const out: SharedField[] = [];
  for (const field of fields) {
    const value = resolve(revisions, field, env, context);
    if (value !== null) out.push({ field, value });
  }
  return out;
}

// Seals the snapshot of the row env/context for `recipient`, stores it with
// POST /shares and returns the link. The link key exists only in this call and
// in the returned link, and for a request in the meta sealed under RK.
export async function createShare(
  host: Api,
  u: Unlocked,
  origin: string,
  secret: SharedSecret,
  recipient: string,
  expiresIn: Expiry,
  row: { env: string; context: string } = { env: "", context: "" },
): Promise<string> {
  const id = newId();
  const linkKey = crypto.getRandomValues(new Uint8Array(SHARE_LINK_KEY_BYTES));
  try {
    const keys = await deriveShareKeys(recipient, linkKey, id);
    const ct = await sealShare(keys, id, secret);
    const metaCt = await sealShareMeta(u.keys, id, {
      name: secret.name,
      recipient: recipient.trim(),
      fields: secret.fields.map((f) => f.field),
      kind: secret.kind,
      env: row.env,
      context: row.context,
      linkKey: secret.kind === "request" ? b64urlEncode(linkKey) : "",
    });
    const body = { id, expires_in: expiresIn, ct: b64Encode(ct), meta_ct: b64Encode(metaCt), token_hash: b64Encode(keys.tokenHash), kind: secret.kind };
    const res = await host.api("POST", "/api/v1/shares", { body: JSON.stringify(body) });
    const refused = sessionRefused(res);
    if (refused) throw refused;
    await host.ok(res);
    return formatShareLink(origin, id, linkKey);
  } finally {
    linkKey.fill(0);
  }
}

export type OwnShare = { id: string; state: string; name: string; recipient: string; expiresAt: number; kind: ShareKind; env: string; context: string; linkKey: string };

// The account's shares by folded secret name (foldKey), from GET /shares. A share whose
// metadata does not open with this vault key is left out.
export async function ownShares(host: Api, u: Unlocked): Promise<Map<string, OwnShare[]>> {
  const res = await host.api("GET", "/api/v1/shares");
  const refused = sessionRefused(res);
  if (refused) throw refused;
  const { shares } = await host.ok<{ shares: { id: string; state: string; meta_ct: string; expires_at: number }[] }>(res);
  const out = new Map<string, OwnShare[]>();
  for (const s of shares) {
    try {
      const m = await openShareMeta(u.keys, s.id, b64Decode(s.meta_ct) ?? new Uint8Array());
      const own = { id: s.id, state: s.state, name: m.name, recipient: m.recipient, expiresAt: s.expires_at, kind: m.kind, env: m.env, context: m.context, linkKey: m.linkKey };
      out.set(foldKey(m.name), [...(out.get(foldKey(m.name)) ?? []), own]);
    } catch {
      console.warn(`skipped share ${s.id}: its metadata does not open`);
    }
  }
  return out;
}

export async function revokeShare(host: Api, id: string): Promise<void> {
  const res = await host.api("POST", `/api/v1/shares/${id}/revoke`);
  const refused = sessionRefused(res);
  if (refused) throw refused;
  await host.ok(res);
}

// The answer of an answered request, opened with the keys the owner derives
// again from the recipient's name and the link key in the meta.
export async function shareAnswer(host: Api, s: Pick<OwnShare, "id" | "recipient" | "linkKey">): Promise<SharedAnswer> {
  const res = await host.api("GET", `/api/v1/shares/${s.id}/answer`);
  const refused = sessionRefused(res);
  if (refused) throw refused;
  const { ct } = await host.ok<{ ct: string }>(res);
  const linkKey = b64urlDecode(s.linkKey) ?? new Uint8Array();
  try {
    return await openShareAnswer(await deriveShareKeys(s.recipient, linkKey, s.id), s.id, b64Decode(ct) ?? new Uint8Array());
  } finally {
    linkKey.fill(0);
  }
}

// Writes the values the owner took from an answer to the request's env and
// context (and the description, when taken) in one write, then ends the
// request, which deletes the answer on the server.
export async function takeAnswer(host: Api, u: Unlocked, s: Pick<OwnShare, "id" | "name" | "env" | "context">, fields: SharedField[], description: string | null): Promise<void> {
  const changes: Change[] = fields.map((f) => ({ op: "set", field: f.field, key: lookupKey(s.env, s.context), value: f.value }));
  if (description !== null) changes.push({ op: "describe", field: "", key: "", value: description });
  if (changes.length) await write(host, u, s.name, changes);
  await revokeShare(host, s.id);
}

const ENDED: Record<string, string> = { taken: "picked up", revoked: "revoked", destroyed: "destroyed", answered: "answered", closed: "closed" };

// The row's line for a share: the time left while open, else how it ended.
// Null from the expiry on, when the server keeps nothing of it.
export function shareTag(s: Pick<OwnShare, "state" | "recipient" | "expiresAt" | "kind">, nowS: number): string | null {
  const left = s.expiresAt - nowS;
  if (left <= 0) return null;
  const open = left >= 86400 ? `${Math.floor(left / 86400)}d` : left >= 3600 ? `${Math.floor(left / 3600)}h` : `${Math.max(1, Math.floor(left / 60))}m`;
  const request = s.kind === "request";
  const ended = request && s.state === "taken" ? "declined" : (ENDED[s.state] ?? s.state);
  return `${request ? "requested" : "shared"} → ${s.recipient} · ${s.state === "open" ? open : ended}`;
}

// ---------------------------------------------------------------------------
// Clipboard: cleared 30 s after a copy. Browsers may refuse a write without a
// recent user action in the tab, so a clear that fails is retried on the next
// pointer or key press here. `cleared` hears whether each attempt worked.

export const CLIPBOARD_S = 30;
export const REVEAL_S = 30;

// Whole seconds until a deadline, so sleep or timer throttling cannot stretch it.
export const secondsLeft = (deadline: number, now = Date.now()): number => Math.max(0, Math.ceil((deadline - now) / 1000));
let clearTimer: number | undefined;
let onCleared: ((done: boolean) => void) | undefined;
const RETRY_EVENTS = ["pointerdown", "keydown"] as const;

function clearClipboard(): void {
  clearTimer = undefined;
  navigator.clipboard.writeText("").then(
    () => onCleared?.(true),
    () => {
      for (const t of RETRY_EVENTS) window.addEventListener(t, retryClear);
      onCleared?.(false);
    },
  );
}

function retryClear(): void {
  for (const t of RETRY_EVENTS) window.removeEventListener(t, retryClear);
  clearClipboard();
}

export async function copy(value: string, cleared: (done: boolean) => void): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    throw new Error("This browser did not allow copying to the clipboard. Show the value and copy it by hand.");
  }
  for (const t of RETRY_EVENTS) window.removeEventListener(t, retryClear);
  window.clearTimeout(clearTimer);
  onCleared = cleared;
  clearTimer = window.setTimeout(clearClipboard, CLIPBOARD_S * 1000);
}

// ---------------------------------------------------------------------------
// Rows: one per value, sorted by entry name, then field, env and context. An
// entry without a value gets one row with value null. A row matches when every
// filter term is in the entry's name or description or in that value's field
// ("default" when empty), env or context. `first` marks the first shown row of
// its entry, which alone carries name and description.

export type Row = { id: string; name: string; description: string; first: boolean; field: string; key: string; env: string; context: string; value: string | null; prefix: number; kind: "single" | "parent" | "child"; guide: string; again: boolean; fields: number };

const part = (s: string) => (s === "*" ? "" : s);
const splitKey = (key: string) => {
  const colon = key.indexOf(":");
  return colon < 0 ? { env: part(key), context: "" } : { env: part(key.slice(0, colon)), context: part(key.slice(colon + 1)) };
};
const order = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
// The list without names that fold alike (foldKey), each in its first spelling.
const uniqueFold = (list: string[]) => {
  const seen = new Map<string, string>();
  for (const x of list) if (!seen.has(foldKey(x))) seen.set(foldKey(x), x);
  return [...seen.values()];
};

export function rows(stored: Map<string, Revision[]>, filter: string): { rows: Row[]; secrets: number; values: number } {
  const terms = filter.toLowerCase().split(/\s+/).filter(Boolean);
  const out: Row[] = [];
  let secrets = 0;
  let values = 0;
  const grouped = entries(stored);
  for (const name of [...grouped.keys()].sort(order)) {
    const cur = current(grouped.get(name)!);
    if (!cur.visible) continue;
    secrets++;
    const variants = [...cur.values.values()].sort((a, b) => order(a.field, b.field) || order(a.key, b.key));
    values += variants.length;
    const tree = variants.some((x) => x.field !== "");
    const hits: Array<{ x: { field: string; key: string; value: string | null }; env: string; context: string }> = [];
    for (const x of variants.length ? variants : [{ field: "", key: "", value: null }]) {
      const { env, context } = splitKey(x.key);
      const hay = [name, cur.description, x.value === null ? "" : x.field || "default", env, context].join(" ").toLowerCase();
      if (terms.every((t) => hay.includes(t))) hits.push({ x, env, context });
    }
    if (!hits.length) continue;
    const row = (x: { field: string; key: string; value: string | null }, env: string, context: string, first: boolean, rest: Partial<Row>): Row => ({
      id: JSON.stringify([name, x.field, x.key]), name, description: cur.description, first, field: x.field, key: x.key, env, context, value: x.value, prefix: 0, kind: "single", guide: "", again: false, fields: 0, ...rest,
    });
    if (tree) {
      out.push(row({ field: "", key: "", value: null }, "", "", true, { id: JSON.stringify([name, null]), kind: "parent", fields: new Set(hits.map((h) => h.x.field)).size }));
    }
    hits.forEach(({ x, env, context }, i) => {
      out.push(
        tree
          ? row(x, env, context, false, { kind: "child", guide: i === hits.length - 1 ? "└─ " : "├─ ", again: i > 0 && hits[i - 1].x.field === x.field })
          : row(x, env, context, i === 0, {}),
      );
    });
  }
  let before = "";
  for (const r of out) {
    if (r.name !== before) r.prefix = sharedPrefix(before, r.name);
    before = r.name;
  }
  return { rows: out, secrets, values };
}

// How many leading characters of `name` repeat the name above, cut back to the last ".", "-" or "_"; never the whole name.
export function sharedPrefix(above: string, name: string): number {
  let n = 0;
  while (n < above.length && n < name.length && above[n] === name[n]) n++;
  const cut = Math.max(...[...name.slice(0, n)].map((c, i) => (/[._-]/.test(c) ? i + 1 : 0)), 0);
  return cut < name.length ? cut : 0;
}

export const rowLabel = (r: Pick<Row, "name" | "field" | "env" | "context">) =>
  [r.name, r.field].filter(Boolean).join(" ") + (r.env ? ` · env ${r.env}` : "") + (r.context ? ` · context ${r.context}` : "");

// The env/context cell: "prod · tenant-a"; a context alone keeps the empty env visible as "· tenant-a".
export const envContext = (r: Pick<Row, "env" | "context">) => (r.context ? `${r.env} · ${r.context}` : r.env);

// A name as text with a line-break opportunity after each ".", "-" and "_".
const breakable = (s: string): Array<string | HTMLElement> =>
  s.split(/(?<=[._-])/).flatMap((t, i) => (i ? [document.createElement("wbr"), t] : [t]));
function nameNodes(name: string, prefix: number): Array<string | HTMLElement> {
  if (!prefix) return breakable(name);
  const dim = document.createElement("span");
  dim.className = "dim";
  dim.append(...breakable(name.slice(0, prefix)));
  return [dim, ...breakable(name.slice(prefix))];
}

// ---------------------------------------------------------------------------
// Keyboard: what a key does where the focus is. "list" is the console outside
// any input; "button" is an action button in it, which handles Enter itself.

export type Command = "filter" | "down" | "up" | "show" | "copy" | "edit" | "share" | "delete" | "new" | "refresh" | "close" | "yes" | "all" | "no" | "first";
export type Focus = "filter" | "editor" | "list" | "button";
const LIST_KEYS: Record<string, Command> = { "/": "filter", ArrowDown: "down", ArrowUp: "up", Enter: "show", c: "copy", e: "edit", s: "share", d: "delete", n: "new", r: "refresh" };

export function command(key: string, focus: Focus, confirming: boolean): Command | null {
  if (key === "Escape") return "close";
  if (focus === "filter") return key === "ArrowDown" || key === "Enter" ? "first" : null;
  if (focus === "editor") return null;
  if (confirming) return key === "y" ? "yes" : key === "a" ? "all" : key === "n" ? "no" : null;
  if (focus === "button" && key === "Enter") return null;
  return LIST_KEYS[key] ?? null;
}

// ---------------------------------------------------------------------------
// View

// Editor input ids come from a counter, so each label points at its own input.
let inputs = 0;

// baseline: the description and the any/any row as typed, for a request from a new secret.
type Grid = { el: HTMLElement; sync: () => void; dirty: () => boolean; baseline: () => { description: string; fields: SharedField[] } };
// What the share panel shares or requests: a row of an entry, or a new secret's grid.
type ShareSource = { name: string; description: string; env: string; context: string; fields: SharedField[] };

export async function vaultView(main: HTMLElement, host: Host): Promise<void> {
  const { h, messageOf } = host;
  const body = h("div", {});
  const signInPrompt = (text?: string) => {
    body.replaceChildren(text ? h("p", { class: "ink" }, text) : "");
    host.login(body);
  };
  main.append(body);

  const unlockedNow = host.unlocked();
  if (!unlockedNow) {
    signInPrompt();
    return;
  }
  const u: Unlocked = unlockedNow;
  // False once another view replaced this one or the tab locked or switched vaults.
  const live = () => body.isConnected && host.unlocked() === u;
  // Runs a pull or write; a refused session swaps the whole view for the sign-in prompt.
  const run = async <T>(task: () => Promise<T>): Promise<T | null> => {
    try {
      const result = await task();
      return live() ? result : null;
    } catch (err) {
      if (!live()) return null;
      if (err instanceof SignInRequired) {
        signInPrompt(err.message);
        return null;
      }
      throw err;
    }
  };

  const loading = h("p", { class: "status", role: "status" }, "Loading your vault …");
  body.append(loading);
  const loaded = await run(() => pull(host, u));
  if (!loaded) return;
  const v = loaded;

  // State. `shown` rows hold values, but the DOM holds one only while it is revealed.
  let shown: Row[] = [];
  let selected: string | null = null;
  let confirming: string | null = null;
  // The one inline panel under an entry: the editor, the share panel or a review.
  let editing: { name: string | null; el: HTMLElement; grid?: Grid } | null = null;
  let shares = new Map<string, OwnShare[]>();
  const revealed = new Map<string, { deadline: number; timer: number; ttl?: HTMLElement }>();
  let deleting = false;

  const filter = h("input", { id: "vault-filter", type: "search", placeholder: "filter by name, field, env, context …", autocomplete: "off", spellcheck: false, "aria-label": "Filter secrets" });
  const refreshButton = h("button", { class: "tbtn", type: "button", title: "Refresh (r)" }, h("kbd", {}, "r"), h("span", { class: "lbl" }, "refresh"), h("span", { class: "ico", "aria-hidden": "true" }, "↻"));
  const newButton = h("button", { class: "tbtn tbtn-primary", type: "button", title: "New secret (n)" }, h("kbd", {}, "n"), h("span", { class: "lbl" }, "new"), h("span", { class: "ico", "aria-hidden": "true" }, "+ new"));
  const count = h("span", {});
  const list = h("ul", { class: "v-list s-list", "aria-label": "Secrets" });
  const statusLine = h("p", { class: "v-status status", role: "status", "aria-live": "polite" });
  const synced = h("span", {});
  const root = h(
    "div",
    { class: "console-view" },
    h("div", { class: "prompt" }, h("label", { class: "ps1", htmlFor: filter.id }, "> ", h("span", { class: "cmd" }, "hort list")), filter, refreshButton, newButton),
    h("div", { class: "meta" }, count, synced),
    h("div", { class: "s-grid" }, h("div", { class: "v-cols s-cols", "aria-hidden": "true" }, ...["name", "env / context", "description"].map((c) => h("span", {}, c))), list),
    h(
      "div",
      { class: "foot" },
      statusLine,
      h(
        "div",
        { class: "hints", "aria-label": "Keyboard shortcuts" },
        ...[["/", "filter"], ["↑ ↓", "select"], ["enter", "show"], ["c", "copy"], ["e", "edit"], ["s", "share"], ["d", "delete"], ["n", "new"], ["esc", "close"], ["g v·d·a", "switch"], ["?", "help"]].map(([k, what]) => h("span", {}, h("kbd", {}, k), what)),
      ),
    ),
  );
  const markSynced = () => (synced.textContent = `synced ${formatTime(Date.now())}`);
  // Listeners on document stay active only while this console is on the page.
  const active = () => root.isConnected && live();

  // One status line. A copy counts down to the clipboard clear.
  let countdown: number | undefined;
  const show = (text: string, kind?: "error" | "ok") => {
    statusLine.textContent = text;
    statusLine.className = `v-status status${kind ? ` status-${kind}` : ""}`;
  };
  const say = (text: string, kind?: "error" | "ok") => {
    window.clearInterval(countdown);
    show(text, kind);
  };

  // Share states degrade alone: when they do not load, the vault still works.
  const loadShares = async (): Promise<void> => {
    try {
      const got = await run(() => ownShares(host, u));
      if (got) shares = got;
    } catch (err) {
      say(messageOf(err), "error");
    }
  };

  const rowById = (id: string | null) => shown.find((r) => r.id === id);
  const focusSelected = () => list.querySelector<HTMLElement>(".v-row.sel")?.focus();

  function draw(): void {
    editing?.grid?.sync();
    const result = rows(v.entries, filter.value);
    shown = result.rows;
    if (selected && !rowById(selected)) selected = null;
    const matched = shown.filter((r) => r.first).length;
    const values = shown.filter((r) => r.value !== null).length;
    count.textContent =
      result.secrets === 0 ? "" : filter.value.trim() ? `${matched} of ${result.secrets} secrets · ${values} of ${result.values} values` : `${result.secrets} secrets · ${result.values} values`;
    if (v.skipped) count.textContent += ` · ${v.skipped} unreadable ${v.skipped === 1 ? "revision" : "revisions"} skipped`;
    const items: HTMLElement[] = [];
    if (editing && editing.name === null) items.push(editing.el);
    if (result.secrets === 0 && !(editing && editing.name === null)) {
      const add = h("button", { class: "tbtn tbtn-primary", type: "button", onclick: () => openEditor(null) }, "+ new secret");
      items.push(h("li", { class: "empty" }, h("p", {}, "No secrets yet."), h("p", {}, "Press ", h("code", {}, "n"), " or ", add, " to add the first one, or run ", h("code", {}, "hort set NAME --value …"), " in a terminal.")));
    } else if (result.secrets && !shown.length) {
      items.push(h("li", { class: "empty" }, h("p", {}, `No secret matches “${filter.value.trim()}”.`), h("p", {}, h("code", {}, "esc"), " clears the filter.")));
    }
    const tabbable = selected ?? shown[0]?.id;
    shown.forEach((r, i) => {
      items.push(rowEl(r, r.id === tabbable));
      const last = shown[i + 1]?.name !== r.name;
      if (last && editing?.name === r.name) items.push(editing.el);
    });
    // Requests for a name the vault does not hold yet, with their own line.
    const terms = filter.value.trim().toLowerCase();
    for (const [folded, list] of shares) {
      if (current(entryOf(v.entries, list[0].name).revisions).visible || !list[0].name.toLowerCase().includes(terms)) continue;
      const line = shareLine(list[0].name);
      if (!line.length) continue;
      items.push(h("li", { class: "v-row first" }, h("span", { class: "key" }, h("span", { class: "c-name", title: list[0].name }, ...breakable(list[0].name))), ...line));
      if (editing?.name != null && foldKey(editing.name) === folded) items.push(editing.el);
    }
    // A panel for a name with no line shown (filtered out, or a request from a new secret) opens on top.
    if (editing && !items.includes(editing.el)) items.unshift(editing.el);
    list.replaceChildren(...items);
  }

  // One row; `tabbable` is the row that Tab reaches (the selected or first one).
  function rowEl(r: Row, tabbable: boolean): HTMLLIElement {
    const rev = revealed.get(r.id);
    const sel = r.id === selected;
    const li = h("li", {
      class: `v-row${r.kind === "child" ? " child" : r.first ? " first" : " cont"}${sel ? " sel" : ""}${rev ? " revealed" : ""}`,
      tabIndex: tabbable ? 0 : -1,
      "aria-label": rowLabel(r),
    });
    const any = (text = "·") => h("span", { class: "any" }, text);
    li.append(
      h(
        "span",
        { class: "key" },
        r.kind === "child"
          ? h("span", { class: `c-name sub${r.again ? " again" : ""}`, title: r.field || undefined }, h("span", { class: "guide" }, r.guide), ...(r.field ? breakable(r.field) : [h("span", { class: "any" }, "(default)")]))
          : h("span", { class: "c-name", title: r.name }, ...nameNodes(r.name, r.prefix), r.kind === "parent" ? h("span", { class: "cnt" }, ` ${r.fields} ${r.fields === 1 ? "field" : "fields"}`) : null),
        h(
          "span",
          { class: "c-env", title: envContext(r) || undefined },
          r.value === null && r.kind === "single" ? h("span", { class: "none" }, "no value yet") : null,
          r.env ? h("span", { class: "tag" }, r.env) : null,
          r.context,
          r.kind !== "parent" && r.value !== null && !r.env && !r.context ? any() : null,
        ),
      ),
    );
    if (confirming === r.id) {
      const no = h("button", { class: "no", type: "button", onclick: () => closeConfirm() }, h("u", {}, "n"), " keep");
      if (r.value === null) {
        const yes = h("button", { class: "yes", type: "button", onclick: () => void deleteGuarded(() => removeEntry(r)) }, h("u", {}, "y"), " delete");
        li.append(h("span", { class: "confirm" }, h("span", { class: "q" }, r.kind === "parent" ? `delete secret ${r.name} with all its values?` : `delete secret ${r.name}?`), no, yes));
      } else {
        const yes = h("button", { class: "yes", type: "button", onclick: () => void deleteGuarded(() => removeValue(r)) }, h("u", {}, "y"), " value");
        const all = h("button", { class: "all", type: "button", onclick: () => void deleteGuarded(() => removeEntry(r)) }, h("u", {}, "a"), " whole secret");
        li.append(h("span", { class: "confirm" }, h("span", { class: "q" }, `delete ${rowLabel(r)}?`), no, all, yes));
      }
    } else {
      const value = rev
        ? h("span", { class: "c-val" }, r.value === "" ? "(empty)" : r.value, (rev.ttl = h("span", { class: "ttl" }, `hides in ${secondsLeft(rev.deadline)} s`)))
        : null;
      const button = (key: string, label: string, run: () => void, cls?: string) =>
        h("button", { type: "button", class: cls, onclick: () => ((selected = r.id), run()) }, h("u", {}, key), ` ${label}`);
      li.append(
        h("span", { class: "c-desc", title: r.first && r.description ? r.description : undefined }, r.first ? r.description : ""),
        ...(r.first ? shareLine(r.name) : []),
        ...(value ? [value] : []),
        h(
          "span",
          { class: "act" },
          r.value === null ? null : button("⏎", rev ? "hide" : "show", () => toggleShow(r)),
          r.value === null ? null : button("c", "copy", () => void copyValue(r)),
          button("e", "edit", () => openEditor(r)),
          button("s", "share", () => openShare(r)),
          button("d", "delete", () => askDelete(r), "danger"),
        ),
      );
    }
    li.addEventListener("click", (e) => {
      if ((e.target as Element).closest("button") || selected === r.id) return;
      select(r.id);
    });
    // Tab into the list selects the focused row without a redraw.
    li.addEventListener("focus", () => {
      if (selected === r.id || confirming) return;
      selected = r.id;
      for (const x of list.querySelectorAll(".v-row.sel")) x.classList.remove("sel");
      li.classList.add("sel");
    });
    li.addEventListener("dblclick", (e) => {
      if (!(e.target as Element).closest("button") && r.value !== null) toggleShow(r);
    });
    return li;
  }

  // The entry's shares until their expiry, with revoke while open and review once answered.
  function shareLine(name: string): HTMLElement[] {
    const nowS = Date.now() / 1000;
    const items = (shares.get(foldKey(name)) ?? []).flatMap((s) => {
      const text = shareTag(s, nowS);
      if (!text) return [];
      const open = s.state === "open";
      const answered = s.state === "answered";
      return [
        h(
          "span",
          { class: open || answered ? "on" : undefined },
          text,
          open ? h("button", { class: "tlink", type: "button", onclick: () => void revoke(s) }, "revoke") : null,
          answered ? h("button", { class: "tlink", type: "button", onclick: () => openReview(s) }, "review") : null,
        ),
      ];
    });
    return items.length ? [h("span", { class: "c-share" }, ...items)] : [];
  }

  async function revoke(s: OwnShare): Promise<void> {
    try {
      if ((await run(() => revokeShare(host, s.id).then(() => true))) === null) return;
    } catch (err) {
      say(messageOf(err), "error");
      return;
    }
    await loadShares();
    draw();
    say(`Revoked the link for ${s.recipient}. It no longer opens.`, "ok");
  }

  // Redraws one row in place, so an open editor keeps what was typed.
  function redrawRow(r: Row): void {
    const i = shown.findIndex((x) => x.id === r.id);
    const old = list.querySelectorAll<HTMLElement>(".v-row")[i];
    if (!old) return;
    const focused = old.contains(document.activeElement);
    const fresh = rowEl(r, old.tabIndex === 0);
    old.replaceWith(fresh);
    if (focused) fresh.focus();
  }

  function select(id: string | null): void {
    selected = id;
    confirming = null;
    draw();
    focusSelected();
  }

  function toggleShow(r: Row): void {
    const rec = revealed.get(r.id);
    if (rec) {
      window.clearInterval(rec.timer);
      revealed.delete(r.id);
    } else {
      const next = { deadline: Date.now() + REVEAL_S * 1000, timer: 0 } as { deadline: number; timer: number; ttl?: HTMLElement };
      next.timer = window.setInterval(() => {
        const left = secondsLeft(next.deadline);
        if (!active() || left <= 0) {
          window.clearInterval(next.timer);
          revealed.delete(r.id);
          const now = rowById(r.id);
          if (active() && now) redrawRow(now);
          return;
        }
        if (next.ttl) next.ttl.textContent = `hides in ${left} s`;
      }, 1000);
      revealed.set(r.id, next);
    }
    redrawRow(r);
  }

  async function copyValue(r: Row): Promise<void> {
    draw();
    focusSelected();
    try {
      await copy(r.value ?? "", (done) => {
        if (!active()) return;
        say(done ? "Clipboard cleared." : "This browser kept the value on the clipboard; Hort clears it on your next click or key press here.", done ? "ok" : "error");
      });
    } catch (err) {
      say(messageOf(err), "error");
      return;
    }
    const deadline = Date.now() + CLIPBOARD_S * 1000;
    const tick = () => show(`copied ${rowLabel(r)} · clipboard clears in ${secondsLeft(deadline)} s`, "ok");
    say("");
    tick();
    countdown = window.setInterval(() => {
      if (secondsLeft(deadline) > 0 && active()) tick();
      else window.clearInterval(countdown);
    }, 1000);
  }

  function askDelete(r: Row): void {
    selected = r.id;
    confirming = r.id;
    draw();
    list.querySelector<HTMLElement>(".confirm .no")?.focus();
  }

  function closeConfirm(): void {
    confirming = null;
    draw();
    focusSelected();
  }

  // One busy guard for both delete paths: no double delete while a write runs.
  async function deleteGuarded(remove: () => Promise<void>): Promise<void> {
    if (deleting) return;
    deleting = true;
    const buttons = () => list.querySelectorAll<HTMLButtonElement>(".confirm .yes, .confirm .all");
    for (const b of buttons()) b.disabled = true;
    try {
      await remove();
    } finally {
      deleting = false;
      for (const b of buttons()) b.disabled = false;
    }
  }

  async function removeEntry(r: Row): Promise<void> {
    try {
      if (!(await run(() => write(host, u, r.name, [{ op: "delete-entry", field: "", key: "", value: "" }]).then(() => true)))) return;
    } catch (err) {
      say(messageOf(err), "error");
      return;
    }
    confirming = null;
    for (const x of shown) if (x.name === r.name) {
      window.clearInterval(revealed.get(x.id)?.timer);
      revealed.delete(x.id);
    }
    draw();
    select(null);
    say(`Deleted ${r.name} with all its values. Earlier values stay in history.`, "ok");
  }

  async function removeValue(r: Row): Promise<void> {
    const index = shown.findIndex((x) => x.id === r.id);
    try {
      if (!(await run(() => write(host, u, r.name, [{ op: "delete", field: r.field, key: r.key, value: "" }]).then(() => true)))) return;
    } catch (err) {
      say(messageOf(err), "error");
      return;
    }
    confirming = null;
    window.clearInterval(revealed.get(r.id)?.timer);
    revealed.delete(r.id);
    draw();
    select(shown[Math.min(index, shown.length - 1)]?.id ?? null);
    say(`Deleted ${rowLabel(r)}. Earlier values stay in history.`, "ok");
  }

  function openEditor(r: Row | null): void {
    if (editing?.grid && (r ? editing.name !== null && foldKey(editing.name) === foldKey(r.name) : editing.name === null)) {
      editing.el.querySelector<HTMLElement>(r ? "textarea" : "input")?.focus();
      return;
    }
    if (!leave()) return;
    confirming = null;
    editing = { name: r?.name ?? null, ...editorEl(r) };
    draw();
    editing.el.querySelector<HTMLElement>(r ? "textarea" : "input")?.focus();
  }

  function openShare(r: Row): void {
    if (!leave()) return;
    confirming = null;
    selected = r.id;
    const fields = shareFields(entryOf(v.entries, r.name).revisions, r.env, r.context);
    openPanel(r.name, shareEl({ name: r.name, description: r.description, env: r.env, context: r.context, fields }, fields.length > 0));
  }

  function openPanel(name: string, el: HTMLElement): void {
    editing = { name, el };
    draw();
    el.querySelector<HTMLElement>("input:not([type=radio])")?.focus();
  }

  function openReview(s: OwnShare): void {
    if (!leave()) return;
    confirming = null;
    openPanel(s.name, reviewEl(s));
  }

  function closeEditor(): void {
    if (!leave()) return;
    editing = null;
    draw();
    focusSelected();
  }

  const text = (value = "", placeholder = "") => h("input", { autocomplete: "off", spellcheck: false, value, placeholder });
  const labelled = (label: string, el: HTMLInputElement | HTMLTextAreaElement, cls?: string) => {
    el.id = `v-${++inputs}`;
    return h("div", { class: cls }, h("label", { htmlFor: el.id }, label), el);
  };

  // False when the open editor holds unsaved edits and the user keeps them.
  const leave = () => !editing?.grid?.dirty() || confirm(editing.name === null ? "Discard the new secret?" : `Close ${editing.name} and discard its unsaved changes?`);

  // Env and context names used anywhere in the loaded vault.
  function usedNames(): { envs: string[]; contexts: string[] } {
    const envs: string[] = [];
    const contexts: string[] = [];
    for (const revisions of entries(v.entries).values()) {
      for (const x of current(revisions).values.values()) {
        const { env, context } = splitKey(x.key);
        if (env) envs.push(env);
        if (context) contexts.push(context);
      }
    }
    return { envs: uniqueFold(envs).sort(order), contexts: uniqueFold(contexts).sort(order) };
  }

  // The value grid: rows are env/context combinations, columns are fields.
  // `commit` receives every change (values, deletions, description) at once;
  // with `cancel` the grid belongs to a new secret (Save / Cancel instead of Save changes / Discard).
  function valueGrid(o: { saved: () => Current; commit: (changes: Change[]) => Promise<void>; done: string; cancel?: () => void }): Grid {
    const cellId = (f: string, key: string) => `${foldKey(f)}\0${foldKey(key)}`;
    const tokens = (input: HTMLInputElement) => uniqueFold(input.value.split(/[,\s]+/).filter(Boolean));
    type Saved = { field: string; key: string; value: string };
    let saved = new Map<string, Saved>();
    let savedDesc = o.saved().description;
    const draft = new Map<string, Saved>(); // cells whose text differs from the saved value
    const removed = new Set<string>(); // folded keys of saved rows marked for deletion
    let newRows: string[] = [];
    let extraFields: string[] = [];
    let masked = true;
    let addingField = false;
    let hideTimer: number | undefined;

    const out = h("span", { class: "g-msg", role: "status" });
    const note = (message: string, error = false) => {
      out.textContent = message;
      out.classList.toggle("err", error);
    };
    const desc = text(savedDesc);
    const table = h("table", { class: "vgrid masked" });
    const sum = h("span", { class: "sum" });
    const saveButton = h("button", { class: "tbtn tbtn-primary", type: "button" }, o.cancel ? "Save" : "Save changes");
    const discardButton = h("button", { class: "tbtn", type: "button" }, o.cancel ? "Cancel" : "Discard");
    const showButton = h("button", { class: "tbtn", type: "button" }, "Show values");
    const envInput = text("", "dev, staging, prod");
    const contextInput = text("", "any");
    const addRowsButton = h("button", { class: "tbtn", type: "button" });
    const envSuggest = h("div", { class: "sugg" });
    const contextSuggest = h("div", { class: "sugg" });

    const eff = (f: string, key: string) => (removed.has(foldKey(key)) ? "" : (draft.get(cellId(f, key))?.value ?? saved.get(cellId(f, key))?.value ?? ""));
    // Where an empty cell gets its value from: the lookup fallback.
    const origin = (f: string, key: string) => {
      const { env, context } = splitKey(key);
      if (context && env && eff(f, lookupKey(env, ""))) return `↳ ${env}`;
      if (key !== "*:*" && eff(f, "*:*")) return "↳ any";
      return "";
    };
    const rowKeys = () => uniqueFold(["*:*", ...[...saved.values()].map((x) => x.key).sort(order), ...newRows]);
    const fields = () => {
      const all = uniqueFold([...[...saved.values()].map((x) => x.field).sort(order), ...extraFields]);
      return all.length ? all : [""];
    };
    const cells = () => [...table.querySelectorAll<HTMLTextAreaElement>(".cell")];

    function diff() {
      const changes: Change[] = [];
      let added = 0;
      let changed = 0;
      let deleted = 0;
      for (const x of draft.values()) {
        if (removed.has(foldKey(x.key))) continue;
        if (x.value === "") {
          changes.push({ op: "delete", field: x.field, key: x.key, value: "" });
          deleted++;
        } else {
          changes.push({ op: "set", field: x.field, key: x.key, value: x.value });
          if (saved.has(cellId(x.field, x.key))) changed++;
          else added++;
        }
      }
      for (const x of saved.values()) {
        if (!removed.has(foldKey(x.key))) continue;
        changes.push({ op: "delete", field: x.field, key: x.key, value: "" });
        deleted++;
      }
      const described = desc.value.trim() !== savedDesc;
      if (described) changes.push({ op: "describe", field: "", key: "", value: desc.value.trim() });
      return { changes, parts: [added && `${added} new`, changed && `${changed} changed`, deleted && `${deleted} deleted`, described && "description"].filter(Boolean) };
    }

    function summary(): void {
      const { parts } = diff();
      sum.textContent = parts.length ? parts.join(" · ") : "No changes";
      saveButton.disabled = !parts.length;
      discardButton.disabled = !parts.length && !o.cancel;
      for (const c of cells()) c.placeholder = origin(c.dataset.f!, c.dataset.key!);
    }

    const fit = (t: HTMLTextAreaElement) => {
      t.style.height = "auto";
      t.style.height = `${t.scrollHeight}px`;
    };

    function drawTable(): void {
      const cols = fields();
      const head = h("tr", {}, h("th", { class: "dim" }, "Env"), h("th", { class: "dim" }, "Context"), ...cols.map((f) => h("th", {}, f || "default")));
      const last = h("th", { class: "g-act" });
      let fieldInput: HTMLInputElement | null = null;
      if (addingField) {
        const fin = h("input", { class: "th-in", placeholder: "field name", "aria-label": "New field name", autocomplete: "off" });
        const commitField = () => {
          if (!addingField) return;
          const typed = fin.value.trim();
          const name = typed === "default" ? "" : typed;
          const known = cols.some((c) => foldKey(c) === foldKey(name));
          addingField = false;
          if (typed && !known) extraFields.push(name);
          note(typed && known ? `Field ${typed} already exists.` : "", Boolean(typed && known));
          drawTable();
          if (typed) cells().find((c) => foldKey(c.dataset.f!) === foldKey(name))?.focus();
        };
        fin.addEventListener("keydown", (e) => {
          if (e.key === "Enter") commitField();
          if (e.key === "Escape") {
            e.stopPropagation();
            fin.value = "";
            commitField();
          }
        });
        fin.addEventListener("blur", commitField);
        last.append(fin);
        fieldInput = fin;
      } else {
        last.append(h("button", { class: "th-add", type: "button", onclick: () => { addingField = true; drawTable(); } }, "+ Field"));
      }
      head.append(last);
      const bodyRows = rowKeys().map((key) => {
        const { env, context } = splitKey(key);
        const gone = removed.has(foldKey(key));
        const tr = h("tr", { class: gone ? "removed" : "" }, h("td", { class: `g-scope${env ? "" : " none"}` }, env || "any"), h("td", { class: `g-scope${context ? "" : " none"}` }, context || "any"));
        for (const f of cols) {
          const id = cellId(f, key);
          const cell = h("textarea", {
            class: "cell",
            rows: 1,
            value: eff(f, key),
            disabled: gone,
            autocomplete: "off",
            "aria-label": `${f || "default"}, env ${env || "any"}, context ${context || "any"}`,
            ...notALogin,
          });
          cell.spellcheck = false;
          Object.assign(cell.dataset, { f, key });
          const mark = () => cell.classList.toggle("changed", draft.has(id));
          mark();
          cell.addEventListener("input", () => {
            if (cell.value === (saved.get(id)?.value ?? "")) draft.delete(id);
            else draft.set(id, { field: f, key, value: cell.value });
            mark();
            fit(cell);
            summary();
          });
          cell.addEventListener("focus", () => fit(cell));
          cell.addEventListener("blur", () => (cell.style.height = ""));
          cell.addEventListener("keydown", (e) => {
            if (e.key !== "Enter" || e.shiftKey || e.metaKey || e.ctrlKey || e.isComposing) return;
            e.preventDefault();
            const column = cells().filter((c) => c.dataset.f === f && !c.disabled);
            column[column.indexOf(cell) + 1]?.focus();
          });
          tr.append(h("td", { class: "val", "data-label": f || "default" }, cell));
        }
        const isNew = newRows.some((k) => foldKey(k) === foldKey(key));
        tr.append(
          h(
            "td",
            { class: "g-act" },
            key === "*:*"
              ? null
              : h(
                  "button",
                  {
                    class: "tbtn",
                    type: "button",
                    "aria-label": `${gone ? "Keep" : "Remove"} ${key}`,
                    onclick: () => {
                      if (isNew) {
                        newRows = newRows.filter((k) => foldKey(k) !== foldKey(key));
                        for (const [id, x] of draft) if (foldKey(x.key) === foldKey(key)) draft.delete(id);
                      } else if (gone) removed.delete(foldKey(key));
                      else removed.add(foldKey(key));
                      drawTable();
                    },
                  },
                  gone ? "Undo" : "Remove",
                ),
          ),
        );
        return tr;
      });
      table.replaceChildren(h("thead", {}, head), h("tbody", {}, ...bodyRows));
      fieldInput?.focus();
      summary();
    }

    function combos(): string[] {
      const envs = tokens(envInput);
      const contexts = tokens(contextInput);
      const have = new Set(rowKeys().map(foldKey));
      const list: string[] = [];
      for (const env of envs.length ? envs : [""]) for (const context of contexts.length ? contexts : [""]) if (!have.has(foldKey(lookupKey(env, context)))) list.push(lookupKey(env, context));
      return list;
    }

    function addState(): void {
      const n = combos().length;
      addRowsButton.textContent = n === 1 ? "Add 1 row" : `Add ${n} rows`;
      addRowsButton.disabled = n === 0;
      for (const [box, input] of [[envSuggest, envInput], [contextSuggest, contextInput]] as const) {
        for (const b of box.children) b.setAttribute("aria-pressed", String(tokens(input).some((t) => foldKey(t) === foldKey(b.textContent ?? ""))));
      }
    }

    function suggest(box: HTMLElement, input: HTMLInputElement, names: string[]): void {
      box.replaceChildren(
        ...names.map((name) =>
          h("button", { type: "button", onclick: () => { const t = tokens(input); input.value = (t.some((x) => foldKey(x) === foldKey(name)) ? t.filter((x) => foldKey(x) !== foldKey(name)) : [...t, name]).join(", "); addState(); } }, name),
        ),
      );
    }

    // Reads the saved entry again, keeps every unsaved edit.
    function sync(): void {
      const cur = o.saved();
      saved = new Map([...cur.values.values()].map((x) => [cellId(x.field, x.key), x]));
      if (desc.value === savedDesc) desc.value = cur.description;
      savedDesc = cur.description;
      const used = usedNames();
      suggest(envSuggest, envInput, used.envs);
      suggest(contextSuggest, contextInput, used.contexts);
      addState();
      drawTable();
    }

    const reset = () => {
      draft.clear();
      removed.clear();
      newRows = [];
      extraFields = [];
    };

    envInput.addEventListener("input", addState);
    contextInput.addEventListener("input", addState);
    desc.addEventListener("input", summary);
    addRowsButton.addEventListener("click", () => {
      const list = combos();
      newRows.push(...list);
      envInput.value = contextInput.value = "";
      addState();
      drawTable();
      cells().find((c) => c.dataset.key === list[0])?.focus();
    });
    showButton.addEventListener("click", () => {
      window.clearTimeout(hideTimer);
      masked = !masked;
      table.classList.toggle("masked", masked);
      showButton.textContent = masked ? "Show values" : "Hide values";
      if (!masked) {
        hideTimer = window.setTimeout(() => {
          masked = true;
          table.classList.add("masked");
          showButton.textContent = "Show values";
        }, REVEAL_S * 1000);
      }
    });
    saveButton.addEventListener("click", async () => {
      const { changes } = diff();
      if (!changes.length) return;
      saveButton.disabled = true;
      note("");
      try {
        await o.commit(changes);
        reset();
        sync();
        note(o.done);
      } catch (err) {
        note(messageOf(err), true);
        summary();
      }
    });
    discardButton.addEventListener("click", () => {
      if (o.cancel) return o.cancel();
      reset();
      desc.value = savedDesc;
      note("");
      drawTable();
    });

    const envField = labelled("Envs", envInput);
    envField.append(envSuggest);
    const contextField = labelled("Contexts", contextInput);
    contextField.append(contextSuggest);
    const el = h(
      "div",
      {},
      labelled("Description", desc, "g-field"),
      h("div", { class: "grid-bar" }, h("h4", {}, "Values"), showButton),
      table,
      h("div", { class: "addrows" }, envField, h("span", { class: "times", "aria-hidden": "true" }, "×"), contextField, addRowsButton),
      h("div", { class: "savebar" }, sum, saveButton, discardButton, out),
    );
    el.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && !saveButton.disabled) {
        e.preventDefault();
        saveButton.click();
      }
    });
    sync();
    const baseline = () => ({ description: desc.value.trim(), fields: fields().map((f) => ({ field: f, value: eff(f, "*:*") })) });
    return { el, sync, dirty: () => diff().changes.length > 0, baseline };
  }

  // The one inline editor: a new secret, or every value and the description of an entry.
  function editorEl(r: Row | null): { el: HTMLElement; grid: Grid } {
    const name = r ? null : text("", "e.g. db");
    const err = h("span", { class: "err", role: "status" });
    const grid = valueGrid({
      saved: () => current(r ? entryOf(v.entries, r.name).revisions : []),
      done: r ? `Saved ${r.name}.` : "",
      cancel: r ? undefined : closeEditor,
      commit: async (changes) => {
        const entry = r?.name ?? name!.value.trim();
        if (!entry) {
          name?.focus();
          throw new Error("Name is required.");
        }
        const result = await run(() => write(host, u, entry, changes));
        if (!result) return;
        if (r) return draw();
        editing = null;
        const first = result.written.find((x) => x.op === "set");
        if (first) selected = JSON.stringify([result.name, first.field, first.key]);
        draw();
        focusSelected();
        say(`Saved ${result.name}.`, "ok");
      },
    });
    let foot: HTMLElement | null = null;
    if (r) {
      const entry = r.name;
      const b = h("button", { class: "tbtn danger", type: "button" }, "delete secret");
      b.addEventListener("click", async () => {
        if (!b.classList.contains("armed")) {
          b.classList.add("armed");
          b.textContent = `confirm: delete ${entry} and all its values`;
          return;
        }
        b.disabled = true;
        try {
          if (!(await run(() => write(host, u, entry, [{ op: "delete-entry", field: "", key: "", value: "" }]).then(() => true)))) return;
          editing = null;
          select(null);
          say(`Deleted ${entry} with all its values. Earlier values stay in history.`, "ok");
        } catch (e) {
          err.textContent = messageOf(e);
        } finally {
          b.disabled = false;
        }
      });
      foot = h("div", { class: "e-foot" }, h("button", { class: "tbtn", type: "button", onclick: closeEditor }, h("kbd", {}, "esc"), "close"), err, h("span", { class: "grow" }), b);
    } else {
      // Asks someone for the values instead: the grid's any/any row as typed is the prefill; nothing is written.
      const ask = h("button", { class: "tbtn", type: "button" }, "request values");
      ask.addEventListener("click", () => {
        const entry = name!.value.trim();
        if (!entry) {
          err.textContent = "Name is required.";
          return name!.focus();
        }
        const base = grid.baseline();
        openPanel(entry, shareEl({ name: entry, description: base.description, env: "", context: "", fields: base.fields }, false));
      });
      foot = h("div", { class: "e-foot" }, ask, err);
    }
    return { el: h("li", { class: "editor" }, h("h3", {}, r ? `> edit ${r.name}` : "> new secret"), name ? labelled("Name", name, "g-field") : null, grid.el, foot), grid };
  }

  // The share panel: share or request, who it is for, which fields, how long;
  // then the link, once. A request may also ask for fields the row lacks.
  function shareEl(src: ShareSource, canShare: boolean): HTMLElement {
    const all = src.fields;
    // A secret without named fields shares its default value and shows no choice.
    const named = all.some((f) => f.field !== "");
    const modes = (["share", "request"] as ShareKind[]).map((k) =>
      h("input", { type: "radio", name: `v-mode-${inputs}`, value: k, checked: k === (canShare ? "share" : "request"), disabled: k === "share" && !canShare }),
    );
    const kind = () => (modes[1].checked ? "request" : "share") as ShareKind;
    const recipient = h("input", { id: `v-${++inputs}`, autocomplete: "off", spellcheck: false, placeholder: "e.g. Lars", ...notALogin });
    const expiry = h("select", { id: `v-${++inputs}` }, ...([3600, 86400, 604800] as Expiry[]).map((s) => h("option", { value: String(s), selected: s === 86400 }, EXPIRY_LABEL[s])));
    const boxes = named ? all.map((f) => h("input", { type: "checkbox", checked: true, "aria-label": f.field || "default" })) : [];
    const more = h("input", { id: `v-${++inputs}`, autocomplete: "off", spellcheck: false, placeholder: "field names, e.g. api_key, secret", ...notALogin });
    const moreField = h("div", { class: "full" }, h("label", { htmlFor: more.id }, "Also ask for"), more);
    const title = h("h3", {});
    const note = h("p", { class: "e-note" });
    const err = h("span", { class: "err", role: "status" });
    const create = h("button", { class: "tbtn tbtn-primary", type: "submit" }, "create link");
    const cancel = h("button", { class: "tbtn", type: "button", onclick: closeEditor }, h("kbd", {}, "esc"), "cancel");
    const scope = envContext(src) ? `Values for env ${src.env || "any"} · context ${src.context || "any"}. ` : "";
    const setMode = () => {
      const request = kind() === "request";
      title.textContent = `> ${request ? "request" : "share"} ${src.name}`;
      moreField.hidden = !request;
      note.textContent = `${scope}${request ? "They see these values, can change or fill them, and send them back once. You review the answer before anything is saved. " : ""}The link opens only for this name. Five wrong names destroy it.`;
    };
    for (const m of modes) m.addEventListener("change", setMode);
    setMode();
    const form = h(
      "form",
      { novalidate: true, ...notALogin },
      h(
        "div",
        { class: "grid" },
        h("div", { class: "full" }, h("label", { class: "check" }, modes[0], "Share"), h("label", { class: "check" }, modes[1], "Request")),
        h("div", { class: "wide" }, h("label", { htmlFor: recipient.id }, "For"), recipient),
        h("div", {}, h("label", { htmlFor: expiry.id }, "Expires in"), expiry),
        named ? h("div", { class: "full" }, h("label", {}, "Fields"), ...boxes.map((b, i) => h("label", { class: "check" }, b, all[i].field || "(default)"))) : null,
        moreField,
      ),
      note,
      h("div", { class: "e-foot" }, create, cancel, err),
    );
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const request = kind() === "request";
      let fields = named ? all.filter((_, i) => boxes[i].checked) : all;
      if (request) {
        const asked = uniqueFold(more.value.split(/[,\s]+/).filter(Boolean).map((f) => (f === "default" ? "" : f)));
        fields = [...fields, ...asked.filter((f) => !all.some((x) => foldKey(x.field) === foldKey(f))).map((field) => ({ field, value: "" }))];
        // Nothing to prefill and nothing asked for: the default field, empty.
        if (!all.length && !fields.length) fields = [{ field: "", value: "" }];
      }
      const name = normalizeShareName(recipient.value);
      err.textContent = !name ? "Type who this is for." : !fields.length ? "Pick at least one field." : "";
      if (err.textContent) return;
      create.disabled = true;
      say("Creating link …");
      try {
        const secret: SharedSecret = { name: src.name, description: src.description, fields, kind: kind() };
        const link = await run(() => createShare(host, u, location.origin, secret, recipient.value, Number(expiry.value) as Expiry, src));
        if (link === null) return;
        say("");
        for (const m of modes) m.disabled = true;
        form.replaceWith(createdEl(link, name));
        await loadShares();
        draw();
      } catch (e) {
        say("");
        err.textContent = messageOf(e);
      } finally {
        create.disabled = false;
      }
    });
    return h("li", { class: "editor" }, title, form);
  }

  // The review of an answered request: per field the row's value next to the
  // answer, each taken or skipped; values reach the DOM only while shown.
  function reviewEl(s: OwnShare): HTMLElement {
    const el = h("li", { class: "editor" }, h("h3", {}, `> review ${s.name} from ${s.recipient}`), h("p", { class: "status", role: "status" }, "Opening the answer …"));
    void (async () => {
      let answer: SharedAnswer | null;
      try {
        answer = await run(() => shareAnswer(host, s));
      } catch (e) {
        el.lastElementChild!.textContent = messageOf(e);
        return;
      }
      if (answer) el.lastElementChild!.replaceWith(reviewForm(s, answer));
    })();
    return el;
  }

  function reviewForm(s: OwnShare, answer: SharedAnswer): HTMLElement {
    const revisions = entryOf(v.entries, s.name).revisions;
    const savedDesc = current(revisions).description;
    type Line = { label: string; now: string | null; got: string; box: HTMLInputElement; secret: boolean; field?: string };
    const lines: Line[] = answer.fields.map((f) => {
      const now = resolve(revisions, f.field, s.env, s.context);
      const box = h("input", { type: "checkbox", checked: f.value !== "" && f.value !== now, disabled: f.value === "", "aria-label": `take ${f.field || "default"}` });
      return { label: f.field || "default", now, got: f.value, box, secret: true, field: f.field };
    });
    if (answer.description !== "" && answer.description !== savedDesc) {
      const box = h("input", { type: "checkbox", checked: savedDesc === "", "aria-label": "take description" });
      lines.push({ label: "description", now: savedDesc || null, got: answer.description, box, secret: false });
    }
    let shownValues = false;
    let hideTimer: number | undefined;
    const cell = (value: string | null, secret: boolean) =>
      value === null ? h("span", { class: "muted" }, "(none)") : value === "" ? h("span", { class: "muted" }, "(empty)") : secret && !shownValues ? h("span", { class: "muted" }, "••••••••") : h("span", { class: "c-val" }, value);
    const tbody = h("tbody", {});
    const drawLines = () =>
      tbody.replaceChildren(...lines.map((l) => h("tr", {}, h("td", { class: "g-scope" }, l.label), h("td", { class: "val", "data-label": "now" }, cell(l.now, l.secret)), h("td", { class: "val", "data-label": "answer" }, cell(l.got, l.secret)), h("td", { class: "g-act" }, h("label", { class: "check" }, l.box, "take")))));
    drawLines();
    const showButton = h("button", { class: "tbtn", type: "button" }, "Show values");
    showButton.addEventListener("click", () => {
      window.clearTimeout(hideTimer);
      shownValues = !shownValues;
      showButton.textContent = shownValues ? "Hide values" : "Show values";
      if (shownValues) hideTimer = window.setTimeout(() => showButton.click(), REVEAL_S * 1000);
      drawLines();
    });
    const err = h("span", { class: "err", role: "status" });
    const take = h("button", { class: "tbtn tbtn-primary", type: "button" });
    const count = () => {
      const n = lines.filter((l) => l.box.checked).length;
      take.textContent = n ? `take ${n} and close` : "close without taking";
    };
    for (const l of lines) l.box.addEventListener("change", count);
    count();
    const finish = async (task: () => Promise<void>, done: string) => {
      take.disabled = decline.disabled = true;
      err.textContent = "";
      try {
        if ((await run(() => task().then(() => true))) === null) return;
      } catch (e) {
        err.textContent = messageOf(e);
        take.disabled = decline.disabled = false;
        return;
      }
      window.clearTimeout(hideTimer);
      editing = null;
      await loadShares();
      draw();
      say(done, "ok");
    };
    take.addEventListener("click", () => {
      const taken = lines.filter((l) => l.box.checked);
      const fields = taken.flatMap((l) => (l.field === undefined ? [] : [{ field: l.field, value: l.got }]));
      const description = taken.find((l) => l.field === undefined)?.got ?? null;
      void finish(() => takeAnswer(host, u, s, fields, description), taken.length ? `Took ${taken.length} from ${s.recipient} into ${s.name}. The answer is deleted.` : "Closed. The answer is deleted.");
    });
    const decline = h("button", { class: "tbtn danger", type: "button" }, "decline");
    decline.addEventListener("click", () => void finish(() => revokeShare(host, s.id), `Declined the answer from ${s.recipient}. It is deleted.`));
    const scope = envContext(s) ? `Values for env ${s.env || "any"} · context ${s.context || "any"}. ` : "";
    return h(
      "div",
      {},
      h("div", { class: "grid-bar" }, h("h4", {}, "Answer"), showButton),
      h("table", { class: "vgrid" }, h("thead", {}, h("tr", {}, h("th", { class: "dim" }, "Field"), h("th", { class: "dim" }, "Now"), h("th", { class: "dim" }, "Answer"), h("th", {}))), tbody),
      h("p", { class: "e-note" }, `${scope}Nothing is saved until you take it.`),
      h("div", { class: "e-foot" }, take, decline, h("button", { class: "tbtn", type: "button", onclick: closeEditor }, h("kbd", {}, "esc"), "close"), err),
    );
  }

  function createdEl(link: string, name: string): HTMLElement {
    const copyLink = h("button", { class: "tbtn tbtn-primary", type: "button" }, "copy link");
    copyLink.addEventListener("click", async () => {
      try {
        await copy(link, (done) => active() && say(done ? "Clipboard cleared." : "This browser kept the link on the clipboard; Hort clears it on your next click or key press here.", done ? "ok" : "error"));
        say(`Link copied. The clipboard clears in ${CLIPBOARD_S} s.`, "ok");
      } catch (err) {
        say(messageOf(err), "error");
      }
    });
    const done = h("button", { class: "tbtn", type: "button", onclick: closeEditor }, h("kbd", {}, "esc"), "done");
    return h(
      "div",
      {},
      h("p", { class: "c-val" }, link),
      h("p", { class: "e-note" }, "They type ", h("code", {}, name), " to open it. This link is shown only now."),
      h("div", { class: "e-foot" }, copyLink, done),
    );
  }

  async function refresh(): Promise<void> {
    refreshButton.disabled = true;
    synced.textContent = "refreshing …";
    try {
      if ((await run(() => pull(host, u))) === null) return;
      await loadShares();
      draw();
      markSynced();
    } catch (err) {
      synced.textContent = "";
      say(messageOf(err), "error");
    } finally {
      refreshButton.disabled = false;
    }
  }

  // Esc closes the innermost open thing: confirm, editor, filter, selection.
  function close(inFilter: boolean): void {
    if (confirming) return closeConfirm();
    if (editing) return closeEditor();
    if (inFilter && filter.value) {
      filter.value = "";
      draw();
    } else if (inFilter) filter.blur();
    else if (selected) select(null);
  }

  function onKey(e: KeyboardEvent): void {
    if (!active()) return document.removeEventListener("keydown", onKey);
    if (e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented) return;
    const t = e.target as HTMLElement;
    if (t !== document.body && !root.contains(t)) return;
    const focus: Focus = t === filter ? "filter" : t.closest(".editor") ? "editor" : t.closest("button") ? "button" : t.matches("input, textarea, select") ? "editor" : "list";
    const cmd = command(e.key, focus, confirming !== null);
    if (!cmd) return;
    e.preventDefault();
    const i = shown.findIndex((r) => r.id === selected);
    const sel = rowById(selected);
    switch (cmd) {
      case "close":
        return close(focus === "filter");
      case "first":
        return shown[0] ? select(shown[0].id) : undefined;
      case "filter":
        filter.focus();
        return filter.select();
      case "down":
        return shown.length ? select(shown[Math.min(i + 1, shown.length - 1)].id) : undefined;
      case "up":
        return i <= 0 ? filter.focus() : select(shown[i - 1].id);
      case "new":
        return openEditor(null);
      case "refresh":
        return void refresh();
      case "yes":
        return void (sel && deleteGuarded(() => (sel.value === null ? removeEntry(sel) : removeValue(sel))));
      case "all":
        return void (sel && sel.value !== null && deleteGuarded(() => removeEntry(sel)));
      case "no":
        return closeConfirm();
    }
    if (!sel) return;
    if (cmd === "edit") return openEditor(sel);
    if (cmd === "delete") return askDelete(sel);
    if (cmd === "share") return openShare(sel);
    if (sel.value === null) return;
    if (cmd === "show") toggleShow(sel);
    else if (cmd === "copy") void copyValue(sel);
  }

  filter.addEventListener("input", () => {
    selected = null;
    confirming = null;
    draw();
  });
  newButton.addEventListener("click", () => openEditor(null));
  refreshButton.addEventListener("click", () => void refresh());
  document.addEventListener("keydown", onKey);

  body.replaceChildren(root);
  markSynced();
  draw();
  if (host.notice) say(host.notice.text, host.notice.kind);
  await loadShares();
  if (active()) draw();
}
