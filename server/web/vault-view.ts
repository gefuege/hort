// /vault (contract §8.1, §8.2): the unlocked vault in this tab. The first
// visit pulls every revision from cursor 0, later visits in the same tab pull
// deltas. Revisions are decrypted and reduced in memory only. Every write goes
// through validateWrite and the Append rule against the in-memory entry, then
// POST /revisions. Values reach the DOM only on an explicit "Show".
import { b64Decode, b64Encode } from "../src/wire";
import { action, api, field, h, messageOf, ok, status, unlocked, type Unlocked } from "./app";
import { accountIdEncode, appendStamp, current, lookupKey, newId, nowNs, openRevision, sealRevision, validateWrite, type Op, type Revision } from "./vault-core";

type Vault = { account: string; cursor: number; entries: Map<string, Revision[]>; ids: Set<string>; skipped: number };
let vault: Vault | null = null;

export function forgetVault(): void {
  vault = null;
}

class SignInRequired extends Error {}

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
async function pull(u: Unlocked): Promise<Vault> {
  const account = accountIdEncode(u.accountId);
  if (vault?.account !== account) vault = { account, cursor: 0, entries: new Map(), ids: new Set(), skipped: 0 };
  const v = vault;
  for (;;) {
    const res = await api("GET", `/api/v1/revisions?after=${v.cursor}`);
    if (res.status === 401) throw new SignInRequired();
    const page = await ok<Page>(res);
    for (const { id, ct } of page.revisions) {
      if (v.ids.has(id)) continue;
      try {
        const { name, revision } = await openRevision(u.keys, id, b64Decode(ct) ?? new Uint8Array());
        remember(v, name, revision);
      } catch (err) {
        v.skipped++;
        console.warn(`skipped revision ${id}: ${messageOf(err)}`);
      }
    }
    v.cursor = page.cursor;
    if (!page.more) return v;
  }
}

type Change = { op: Op; field: string; key: string; value: string };

// Pulls deltas first, so the Append rule sees writes from other devices,
// then stamps, validates, seals and pushes the changes as one batch.
async function write(u: Unlocked, name: string, changes: Change[]): Promise<void> {
  const v = await pull(u);
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
  const res = await api("POST", "/api/v1/revisions", { body: JSON.stringify({ revisions }) });
  if (res.status === 401) throw new SignInRequired();
  const result = await ok<{ accepted: string[]; duplicate: string[] }>(res);
  const stored = new Set([...result.accepted, ...result.duplicate]);
  for (const r of built) if (stored.has(r.id)) remember(v, name, r);
}

// ---------------------------------------------------------------------------
// Clipboard: cleared 30 s after a copy. Browsers allow the write only while
// the tab has focus, so a clear that fails is retried when the tab regains it.

let clearTimer: number | undefined;

function clearClipboard(): void {
  clearTimer = undefined;
  navigator.clipboard.writeText("").catch(() => window.addEventListener("focus", clearClipboard, { once: true }));
}

async function copy(value: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    throw new Error("This browser did not allow copying to the clipboard. Use Show and copy the value by hand.");
  }
  window.removeEventListener("focus", clearClipboard);
  window.clearTimeout(clearTimer);
  clearTimer = window.setTimeout(clearClipboard, 30_000);
}

// ---------------------------------------------------------------------------
// View

const splitKey = (key: string) => {
  const colon = key.indexOf(":");
  return colon < 0 ? { env: key, context: "*" } : { env: key.slice(0, colon), context: key.slice(colon + 1) };
};

function variantLabel(fieldName: string, key: string): string {
  const { env, context } = splitKey(key);
  return [fieldName || "default", env !== "*" && `env ${env}`, context !== "*" && `context ${context}`].filter(Boolean).join(" · ");
}

// The add form and an open editor show the same labels, so ids come from a counter.
let inputs = 0;
const textInput = (props: Record<string, unknown> = {}) => h("input", { id: `v-${++inputs}`, autocomplete: "off", spellcheck: false, ...props });
const valueInput = () => h("textarea", { id: `v-${++inputs}`, autocomplete: "off", spellcheck: false, rows: 3, required: true });

function signInPrompt(main: HTMLElement, text: string): void {
  main.append(
    h("p", { class: "sec-intro" }, text),
    h("div", { class: "actions" }, h("a", { class: "btn btn-primary", href: "/login" }, "Sign in with a passkey"), h("a", { class: "btn btn-ghost", href: "/recover" }, "Use your Emergency Kit")),
  );
}

export async function vaultView(main: HTMLElement): Promise<void> {
  const u = unlocked;
  if (!u) {
    signInPrompt(main, "Your vault is locked in this tab. Sign in with a passkey that unlocks it, or use your Emergency Kit.");
    return;
  }
  const out = status();
  main.append(out.el);
  out.set("Loading your vault …");
  let v: Vault;
  try {
    v = await pull(u);
  } catch (err) {
    if (!(err instanceof SignInRequired)) throw err;
    out.set("");
    signInPrompt(main, "Your vault is unlocked, but loading it needs a passkey sign-in on this device.");
    return;
  }
  out.set("");

  let open: string | null = null; // entry whose editor is shown
  const search = h("input", { class: "search", type: "search", placeholder: "Search", "aria-label": "Search secrets", autocomplete: "off", spellcheck: false });
  const addButton = h("button", { class: "btn btn-primary", type: "button" }, "Add secret");
  const refreshButton = h("button", { class: "btn btn-ghost", type: "button" }, "Refresh");
  const addArea = h("div", {});
  const count = h("p", { class: "muted vault-count" });
  const list = h("ul", { class: "entries" });

  // Runs a write, then redraws from memory; errors stay next to the form.
  const save = async (name: string, changes: Change[], done: string) => {
    try {
      await write(u, name, changes);
    } catch (err) {
      if (err instanceof SignInRequired) throw new Error("Your sign-in has expired. Sign in with your passkey again.");
      throw err;
    }
    draw();
    out.set(done, "ok");
  };

  function editor(name: string, description: string): HTMLElement {
    const setOut = status();
    const f = textInput({ placeholder: "default" });
    const env = textInput({ placeholder: "any" });
    const ctx = textInput({ placeholder: "any" });
    const value = valueInput();
    const setForm = h(
      "form",
      { class: "form" },
      field("Field", f),
      h("div", { class: "field-row" }, field("Env", env), field("Context", ctx)),
      field("Value", value),
      h("div", { class: "actions" }, h("button", { class: "btn btn-primary", type: "submit" }, "Save value")),
      setOut.el,
    );
    submit(setForm, setOut, () =>
      save(name, [{ op: "set", field: f.value.trim(), key: lookupKey(env.value.trim(), ctx.value.trim()), value: value.value }], `Saved a value for ${name}.`),
    );

    const descOut = status();
    const desc = textInput({ value: description });
    const descForm = h("form", { class: "form" }, field("Description", desc), h("div", { class: "actions" }, h("button", { class: "btn btn-ghost", type: "submit" }, "Save description")), descOut.el);
    submit(descForm, descOut, () => save(name, [{ op: "describe", field: "", key: "", value: desc.value.trim() }], `Saved the description of ${name}.`));

    const delOut = status();
    const del = h("button", { class: "btn btn-ghost btn-danger", type: "button" }, "Delete secret");
    action(del, delOut, async () => {
      if (!confirm(`Delete ${name} with all its values? Earlier values stay in history.`)) return;
      open = null;
      await save(name, [{ op: "delete-entry", field: "", key: "", value: "" }], `Deleted ${name}.`);
    });

    return h(
      "div",
      { class: "editor" },
      h("h4", { class: "panel-h" }, "Set a value"),
      h("p", { class: "muted" }, "Leave field, env and context empty for the default value. A new value replaces the current one; earlier values stay in history."),
      setForm,
      h("h4", { class: "panel-h" }, "Description"),
      descForm,
      h("div", { class: "actions" }, del),
      delOut.el,
    );
  }

  function entryEl(name: string, revisions: Revision[]): HTMLElement {
    const { values, description } = current(revisions);
    const rowOut = status();
    const variants = [...values.values()].sort((a, b) => (a.field === b.field ? (a.key < b.key ? -1 : 1) : a.field < b.field ? -1 : 1));
    const rows = variants.map((x) => {
      const shown = h("code", { class: "variant-value" });
      let hideTimer: number | undefined;
      const show = h("button", { class: "btn btn-ghost btn-small", type: "button" }, "Show");
      show.addEventListener("click", () => {
        window.clearTimeout(hideTimer);
        if (shown.textContent) {
          shown.textContent = "";
          show.textContent = "Show";
          return;
        }
        shown.textContent = x.value === "" ? "(empty)" : x.value;
        show.textContent = "Hide";
        hideTimer = window.setTimeout(() => {
          shown.textContent = "";
          show.textContent = "Show";
        }, 30_000);
      });
      const copyButton = h("button", { class: "btn btn-ghost btn-small", type: "button" }, "Copy");
      action(copyButton, rowOut, async () => {
        await copy(x.value);
        rowOut.set("Copied. The clipboard is cleared in 30 s.", "ok");
      });
      const del = h("button", { class: "btn btn-ghost btn-small", type: "button", "aria-label": `Delete ${variantLabel(x.field, x.key)}` }, "Delete");
      action(del, rowOut, async () => {
        if (!confirm(`Delete the value ${variantLabel(x.field, x.key)} of ${name}? Earlier values stay in history.`)) return;
        await save(name, [{ op: "delete", field: x.field, key: x.key, value: "" }], `Deleted a value of ${name}.`);
      });
      return h("li", { class: "variant" }, h("span", { class: "variant-label" }, variantLabel(x.field, x.key)), h("span", { class: "variant-actions" }, show, copyButton, del), shown);
    });
    const edit = h("button", { class: "btn btn-ghost btn-small", type: "button", "aria-expanded": String(open === name) }, open === name ? "Close" : "Edit");
    edit.addEventListener("click", () => {
      open = open === name ? null : name;
      draw();
    });
    return h(
      "li",
      { class: "entry" },
      h("div", { class: "entry-head" }, h("h3", { class: "entry-name" }, name), edit),
      description ? h("p", { class: "entry-desc muted" }, description) : null,
      rows.length ? h("ul", { class: "variants" }, ...rows) : h("p", { class: "muted" }, "No value yet."),
      rowOut.el,
      open === name ? editor(name, description) : null,
    );
  }

  function draw(): void {
    const terms = search.value.toLowerCase().split(/\s+/).filter(Boolean);
    const visible = [...v.entries]
      .map(([name, revisions]) => ({ name, revisions, cur: current(revisions) }))
      .filter((e) => e.cur.visible)
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    // Same haystack as `hort search`: name, description, fields, env and context.
    const matches = visible.filter((e) => {
      const words = [e.name, e.cur.description];
      for (const x of e.cur.values.values()) words.push(x.field, ...Object.values(splitKey(x.key)));
      const hay = words.join(" ").toLowerCase();
      return terms.every((t) => hay.includes(t));
    });
    count.textContent =
      visible.length === 0 ? "No secrets yet." : terms.length ? `${matches.length} of ${visible.length} secrets` : `${visible.length} ${visible.length === 1 ? "secret" : "secrets"}`;
    if (v.skipped) count.textContent += ` · ${v.skipped} unreadable ${v.skipped === 1 ? "revision" : "revisions"} skipped`;
    list.replaceChildren(...matches.map((e) => entryEl(e.name, e.revisions)));
  }

  function addForm(): HTMLElement {
    const formOut = status();
    const name = textInput({ required: true });
    const f = textInput({ placeholder: "default" });
    const env = textInput({ placeholder: "any" });
    const ctx = textInput({ placeholder: "any" });
    const value = valueInput();
    const desc = textInput();
    const form = h(
      "form",
      { class: "form panel" },
      h("h2", { class: "panel-h" }, "Add secret"),
      field("Name", name),
      field("Field", f),
      h("div", { class: "field-row" }, field("Env", env), field("Context", ctx)),
      field("Value", value),
      field("Description", desc),
      h("div", { class: "actions" }, h("button", { class: "btn btn-primary", type: "submit" }, "Save"), h("button", { class: "btn btn-ghost", type: "button", onclick: () => addArea.replaceChildren() }, "Cancel")),
      formOut.el,
    );
    submit(form, formOut, async () => {
      const n = name.value.trim();
      const changes: Change[] = [{ op: "set", field: f.value.trim(), key: lookupKey(env.value.trim(), ctx.value.trim()), value: value.value }];
      const d = desc.value.trim();
      if (d && d !== current(v.entries.get(n) ?? []).description) changes.push({ op: "describe", field: "", key: "", value: d });
      await save(n, changes, `Saved ${n}.`);
      addArea.replaceChildren();
    });
    return form;
  }

  search.addEventListener("input", draw);
  addButton.addEventListener("click", () => {
    addArea.replaceChildren(addForm());
    addArea.querySelector("input")?.focus();
  });
  action(refreshButton, out, async () => {
    await pull(u);
    draw();
    out.set("");
  });

  main.append(h("div", { class: "vault-bar" }, search, addButton, refreshButton), addArea, count, list);
  draw();
}

// Form submit with the submit button disabled and errors shown in place.
function submit(form: HTMLFormElement, out: ReturnType<typeof status>, run: () => Promise<void>): void {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = form.querySelector<HTMLButtonElement>("button[type=submit]");
    if (button) button.disabled = true;
    out.set("");
    try {
      await run();
    } catch (err) {
      out.set(messageOf(err), "error");
    } finally {
      if (button) button.disabled = false;
    }
  });
}
