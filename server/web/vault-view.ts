// /vault (contract §8.1, §8.2): the vault view of the console, for the unlocked vault in this tab. The first
// visit pulls every revision from cursor 0, later visits in the same tab pull
// deltas. Revisions are decrypted and reduced in memory only. Every write goes
// through validateWrite and the Append rule against the in-memory entry, then
// POST /revisions. Values reach the DOM only on an explicit "Show".
import { b64Decode, b64Encode } from "../src/wire";
import { accountIdEncode, appendStamp, current, lookupKey, newId, nowNs, openRevision, sealRevision, validateWrite, type AccountKeys, type Op, type Revision } from "./vault-core";

type Child = Node | string | null | false | undefined;
type Unlocked = { accountId: Uint8Array; keys: AccountKeys };
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
  if (res.status === 401) return new SignInRequired("Your vault is unlocked, but loading it needs a passkey sign-in on this device.");
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

type Change = { op: Op; field: string; key: string; value: string };

// Pulls deltas first, so the Append rule sees writes from other devices,
// then stamps, validates, seals and pushes the changes as one batch.
export async function write(host: Api, u: Unlocked, name: string, changes: Change[]): Promise<void> {
  const v = await pull(host, u);
  const known = [...(v.entries.get(name) ?? [])];
  const built: Revision[] = [];
  for (const c of changes) {
    const r: Revision = { id: newId(), recordedAt: appendStamp(known, nowNs()), ...c };
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
}


// ---------------------------------------------------------------------------
// Clipboard: cleared 30 s after a copy. Browsers may refuse a write without a
// recent user action in the tab, so a clear that fails is retried on the next
// pointer or key press here. `cleared` hears whether each attempt worked.

const CLIPBOARD_S = 30;
const REVEAL_S = 30;

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

async function copy(value: string, cleared: (done: boolean) => void): Promise<void> {
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

export type Row = { id: string; name: string; description: string; first: boolean; field: string; key: string; env: string; context: string; value: string | null };

const part = (s: string) => (s === "*" ? "" : s);
const splitKey = (key: string) => {
  const colon = key.indexOf(":");
  return colon < 0 ? { env: part(key), context: "" } : { env: part(key.slice(0, colon)), context: part(key.slice(colon + 1)) };
};
const order = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export function rows(entries: Map<string, Revision[]>, filter: string): { rows: Row[]; secrets: number; values: number } {
  const terms = filter.toLowerCase().split(/\s+/).filter(Boolean);
  const out: Row[] = [];
  let secrets = 0;
  let values = 0;
  for (const name of [...entries.keys()].sort(order)) {
    const cur = current(entries.get(name)!);
    if (!cur.visible) continue;
    secrets++;
    const variants = [...cur.values.values()].sort((a, b) => order(a.field, b.field) || order(a.key, b.key));
    values += variants.length;
    let first = true;
    for (const x of variants.length ? variants : [{ field: "", key: "", value: null }]) {
      const { env, context } = splitKey(x.key);
      const hay = [name, cur.description, x.value === null ? "" : x.field || "default", env, context].join(" ").toLowerCase();
      if (!terms.every((t) => hay.includes(t))) continue;
      out.push({ id: JSON.stringify([name, x.field, x.key]), name, description: cur.description, first, field: x.field, key: x.key, env, context, value: x.value });
      first = false;
    }
  }
  return { rows: out, secrets, values };
}

export const rowLabel = (r: Pick<Row, "name" | "field" | "env" | "context">) =>
  [r.name, r.field].filter(Boolean).join(" ") + (r.env ? ` · env ${r.env}` : "") + (r.context ? ` · context ${r.context}` : "");

// ---------------------------------------------------------------------------
// Keyboard: what a key does where the focus is. "list" is the console outside
// any input; "button" is an action button in it, which handles Enter itself.

export type Command = "filter" | "down" | "up" | "show" | "copy" | "edit" | "delete" | "new" | "refresh" | "close" | "yes" | "all" | "no" | "first";
export type Focus = "filter" | "editor" | "list" | "button";
const LIST_KEYS: Record<string, Command> = { "/": "filter", ArrowDown: "down", ArrowUp: "up", Enter: "show", c: "copy", e: "edit", d: "delete", n: "new", r: "refresh" };

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
  let editing: { name: string | null; el: HTMLElement } | null = null;
  const revealed = new Map<string, { deadline: number; timer: number; ttl?: HTMLElement }>();
  let deleting = false;

  const filter = h("input", { id: "vault-filter", type: "search", placeholder: "filter by name, field, env, context …", autocomplete: "off", spellcheck: false, "aria-label": "Filter secrets" });
  const refreshButton = h("button", { class: "tbtn", type: "button", title: "Refresh (r)" }, h("kbd", {}, "r"), h("span", { class: "lbl" }, "refresh"), h("span", { class: "ico", "aria-hidden": "true" }, "↻"));
  const newButton = h("button", { class: "tbtn tbtn-primary", type: "button", title: "New secret (n)" }, h("kbd", {}, "n"), h("span", { class: "lbl" }, "new"), h("span", { class: "ico", "aria-hidden": "true" }, "+ new"));
  const count = h("span", {});
  const list = h("ul", { class: "v-list", "aria-label": "Secrets" });
  const statusLine = h("p", { class: "v-status status", role: "status", "aria-live": "polite" });
  const synced = h("span", {});
  const root = h(
    "div",
    { class: "console-view" },
    h("div", { class: "prompt" }, h("label", { class: "ps1", htmlFor: filter.id }, "> ", h("span", { class: "cmd" }, "hort list")), filter, refreshButton, newButton),
    h("div", { class: "meta" }, count, synced),
    h("div", { class: "v-cols", "aria-hidden": "true" }, ...["name", "field", "env", "context", "value", "description"].map((c) => h("span", {}, c))),
    list,
    h(
      "div",
      { class: "foot" },
      statusLine,
      h(
        "div",
        { class: "hints", "aria-label": "Keyboard shortcuts" },
        ...[["/", "filter"], ["↑ ↓", "select"], ["enter", "show"], ["c", "copy"], ["e", "edit"], ["d", "delete"], ["n", "new"], ["esc", "close"], ["g v·d·a", "switch"], ["?", "help"]].map(([k, what]) => h("span", {}, h("kbd", {}, k), what)),
      ),
    ),
  );
  const markSynced = () => (synced.textContent = `synced ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`);
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

  const rowById = (id: string | null) => shown.find((r) => r.id === id);
  const focusSelected = () => list.querySelector<HTMLElement>(".v-row.sel")?.focus();

  function draw(): void {
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
    list.replaceChildren(...items);
  }

  // One row; `tabbable` is the row that Tab reaches (the selected or first one).
  function rowEl(r: Row, tabbable: boolean): HTMLLIElement {
    const rev = revealed.get(r.id);
    const sel = r.id === selected;
    const li = h("li", {
      class: `v-row${r.first ? " first" : " cont"}${sel ? " sel" : ""}${rev ? " revealed" : ""}`,
      tabIndex: tabbable ? 0 : -1,
      "aria-label": rowLabel(r),
    });
    const any = (text = "·") => h("span", { class: "any" }, text);
    li.append(
      h(
        "span",
        { class: "key" },
        h("span", { class: "c-name" }, r.name),
        h("span", { class: "c-field" }, r.value === null ? "" : r.field || any("default")),
        h("span", { class: "c-env" }, r.env || any()),
        h("span", { class: "c-ctx" }, r.context || any()),
      ),
    );
    if (confirming === r.id) {
      const no = h("button", { class: "no", type: "button", onclick: () => closeConfirm() }, h("u", {}, "n"), " keep");
      if (r.value === null) {
        const yes = h("button", { class: "yes", type: "button", onclick: () => void deleteGuarded(() => removeEntry(r)) }, h("u", {}, "y"), " delete");
        li.append(h("span", { class: "confirm" }, h("span", { class: "q" }, `delete secret ${r.name}?`), no, yes));
      } else {
        const yes = h("button", { class: "yes", type: "button", onclick: () => void deleteGuarded(() => removeValue(r)) }, h("u", {}, "y"), " value");
        const all = h("button", { class: "all", type: "button", onclick: () => void deleteGuarded(() => removeEntry(r)) }, h("u", {}, "a"), " whole secret");
        li.append(h("span", { class: "confirm" }, h("span", { class: "q" }, `delete ${rowLabel(r)}?`), no, all, yes));
      }
    } else {
      const value = h("span", { class: `c-val${rev ? " shown" : ""}${r.value === null ? " none" : ""}` });
      if (r.value === null) value.textContent = "no value yet";
      else if (rev) {
        rev.ttl = h("span", { class: "ttl" }, `hides in ${secondsLeft(rev.deadline)} s`);
        value.append(r.value === "" ? "(empty)" : r.value, rev.ttl);
      } else value.textContent = "••••••••••";
      const button = (key: string, label: string, run: () => void, cls?: string) =>
        h("button", { type: "button", class: cls, onclick: () => ((selected = r.id), run()) }, h("u", {}, key), ` ${label}`);
      li.append(
        value,
        h("span", { class: "c-desc" }, r.first ? r.description : ""),
        h(
          "span",
          { class: "act" },
          r.value === null ? null : button("⏎", rev ? "hide" : "show", () => toggleShow(r)),
          r.value === null ? null : button("c", "copy", () => void copyValue(r)),
          button("e", "edit", () => openEditor(r)),
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
    confirming = null;
    editing = { name: r?.name ?? null, el: editorEl(r) };
    draw();
    editing.el.querySelector<HTMLElement>(r ? "textarea" : "input")?.focus();
  }

  function closeEditor(): void {
    editing = null;
    draw();
    focusSelected();
  }

  // The one inline editor: a new secret, or a value and the description of an entry.
  function editorEl(r: Row | null): HTMLElement {
    const input = (label: string, el: HTMLInputElement | HTMLTextAreaElement, cls?: string) => {
      el.id = `v-${++inputs}`;
      return h("div", { class: cls }, h("label", { htmlFor: el.id }, label), el);
    };
    const text = (value = "", placeholder = "") => h("input", { autocomplete: "off", spellcheck: false, value, placeholder });
    const name = r ? null : text("", "e.g. db");
    if (name) name.required = true;
    const field = text(r?.field, "default");
    const env = text(r?.env, "any");
    const ctx = text(r?.context, "any");
    const value = h("textarea", { autocomplete: "off", spellcheck: false, rows: 1, placeholder: r ? "unchanged" : "" });
    const desc = text(r?.description);
    const err = h("span", { class: "err", role: "status" });
    const saveButton = h("button", { class: "tbtn tbtn-primary", type: "submit" }, "save");
    const cancel = h("button", { class: "tbtn", type: "button", onclick: closeEditor }, h("kbd", {}, "esc"), "cancel");
    let deleteEntry: HTMLButtonElement | null = null;
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
      deleteEntry = b;
    }
    const form = h(
      "form",
      { novalidate: true },
      h(
        "div",
        { class: "grid" },
        name ? input("Name", name) : null,
        input("Field", field, r ? "wide" : undefined),
        input("Env", env),
        input("Context", ctx),
        input(r ? "New value" : "Value", value, "full"),
        input("Description", desc, "full"),
      ),
      h("p", { class: "e-note" }, "Leave field, env and context empty for the default value. A new value replaces the current one; earlier values stay in history."),
      h("div", { class: "e-foot" }, saveButton, cancel, err, h("span", { class: "grow" }), deleteEntry),
    );
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const entry = r?.name ?? name!.value.trim();
      if (!entry) {
        err.textContent = "Name is required.";
        name?.focus();
        return;
      }
      const set = { op: "set" as const, field: field.value.trim(), key: lookupKey(env.value.trim(), ctx.value.trim()), value: value.value };
      const changes: Change[] = r && set.value === "" ? [] : [set];
      const d = desc.value.trim();
      if (d !== current(v.entries.get(entry) ?? []).description && (r || d)) changes.push({ op: "describe", field: "", key: "", value: d });
      if (!changes.length) return closeEditor();
      saveButton.disabled = true;
      err.textContent = "";
      try {
        if (!(await run(() => write(host, u, entry, changes).then(() => true)))) return;
        editing = null;
        const savedKey = { name: entry, ...splitKey(set.key), field: set.field };
        selected = changes[0].op === "set" ? JSON.stringify([entry, set.field, set.key]) : selected;
        draw();
        focusSelected();
        say(`Saved ${changes[0].op === "set" ? rowLabel(savedKey) : entry}.`, "ok");
      } catch (e) {
        err.textContent = messageOf(e);
      } finally {
        saveButton.disabled = false;
      }
    });
    return h("li", { class: "editor" }, h("h3", {}, r ? `> edit ${r.name}` : "> new secret"), form);
  }

  async function refresh(): Promise<void> {
    refreshButton.disabled = true;
    synced.textContent = "refreshing …";
    try {
      if ((await run(() => pull(host, u))) === null) return;
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
}
