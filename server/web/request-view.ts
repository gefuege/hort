// Hort web app: /r/<id>, the page for an agent's secret request (contract §7.3).
// The page decrypts the request's metadata, shows what is asked for and
// whether a value exists for each requested field (never the value), and
// stores the values the user types in one POST /requests/{id}/fulfill. The vault key and
// everything decrypted here stay in memory; no innerHTML (Trusted Types).
import { b64Decode, b64Encode } from "../src/wire";
import { notALogin } from "./not-a-login";
import {
  appendStamp,
  current,
  entryOf,
  foldKey,
  lookupKey,
  newId,
  nowNs,
  openRequestMeta,
  openRevision,
  sealRevision,
  spelling,
  validateWrite,
  type AccountKeys,
  type Revision,
  type RequestMeta,
} from "./vault-core";

type Child = Node | string | null | false | undefined;
type StatusOut = { el: HTMLElement; set: (text: string, kind?: "error" | "ok") => void };

// What the page needs from the app shell, which owns the unlocked vault.
export type Host = {
  h: <K extends keyof HTMLElementTagNameMap>(tag: K, props?: Record<string, unknown>, ...children: Child[]) => HTMLElementTagNameMap[K];
  messageOf: (err: unknown) => string;
  api: (method: string, path: string, o?: { body?: string }) => Promise<Response>;
  ok: <T>(res: Response) => Promise<T>;
  // Keys of the unlocked vault when there is a passkey session as well, else null.
  keys: () => AccountKeys | null;
  // The server no longer accepts the session.
  sessionLost: () => void;
  // Renders passkey sign-in (and unlock) into `into`; `done` runs once the vault is unlocked.
  login: (into: HTMLElement, done: () => void) => void;
  // Closes the request and returns to the vault, with the outcome for its status line.
  done: (text?: string, kind?: "ok") => void;
};

export const REQUEST_PATH = /^\/r\/([0-9a-f]{32})$/;

class SessionLost extends Error {}

type RequestRecord = { status: string; meta_ct: string; revision_ids: string[] };

export async function requestView(main: HTMLElement, host: Host, path: string): Promise<void> {
  const { h } = host;
  const id = REQUEST_PATH.exec(path)![1];
  const body = h("div");
  const line = h("p", { class: "v-status status", role: "status", "aria-live": "polite" });
  const out: StatusOut = {
    el: line,
    set(text, kind) {
      line.textContent = text;
      line.className = `v-status status${kind ? ` status-${kind}` : ""}`;
    },
  };
  const root = h(
    "div",
    { class: "console-view" },
    h("div", { class: "prompt static" }, h("span", { class: "ps1" }, "> ", h("span", { class: "cmd" }, "hort request"))),
    body,
    h("div", { class: "foot" }, line, h("div", { class: "hints", "aria-label": "Keyboard shortcuts" }, ...[["enter", "store"], ["esc", "back to vault"], ["g v·d·a", "switch"], ["?", "help"]].map(([k, what]) => h("span", {}, h("kbd", {}, k), what)))),
  );
  main.append(root);
  const onKey = (e: KeyboardEvent) => {
    if (!root.isConnected) return document.removeEventListener("keydown", onKey);
    if (e.key !== "Escape" || e.defaultPrevented) return;
    // Escape inside the form is not "leave": it must not discard what was typed.
    if (e.target instanceof Element && e.target.closest("form, input, textarea, select")) return;
    e.preventDefault();
    host.done();
  };
  document.addEventListener("keydown", onKey);
  const show = async (): Promise<void> => {
    body.replaceChildren();
    out.set("");
    try {
      await load(body, host, id, show, out);
    } catch (err) {
      if (!(err instanceof SessionLost)) {
        out.set(host.messageOf(err), "error");
        return;
      }
      host.sessionLost();
      const slot = h("div");
      body.replaceChildren(slot);
      host.login(slot, () => void show());
    }
  };
  await show();
}

async function get(host: Host, path: string): Promise<Response> {
  const res = await host.api("GET", path);
  if (res.status === 401) throw new SessionLost();
  return res;
}

// Pulls every revision after `after`, keeps those of the secret `name` by
// stored name (any spelling that folds like it) and returns the new cursor.
// Envelopes that do not decrypt are skipped.
async function pull(host: Host, keys: AccountKeys, name: string, after: number, into: Map<string, Revision[]>): Promise<number> {
  let cursor = after;
  for (;;) {
    const page = await host.ok<{ revisions: { id: string; ct: string }[]; cursor: number; more: boolean }>(
      await get(host, `/api/v1/revisions?after=${cursor}&limit=500`),
    );
    for (const r of page.revisions) {
      try {
        const opened = await openRevision(keys, r.id, b64Decode(r.ct)!);
        if (foldKey(opened.name) === foldKey(name)) into.set(opened.name, [...(into.get(opened.name) ?? []), opened.revision]);
      } catch {
        // not readable with this vault key
      }
    }
    cursor = page.cursor;
    if (!page.more) return cursor;
  }
}

async function load(body: HTMLElement, host: Host, id: string, retry: () => Promise<void>, out: StatusOut): Promise<void> {
  const { h } = host;
  const keys = host.keys();
  if (!keys) throw new SessionLost();

  const res = await get(host, `/api/v1/requests/${id}`);
  if (res.status === 404) {
    body.append(
      h(
        "section",
        { class: "block" },
        h("h3", {}, "> request not found"),
        h("p", { class: "ink" }, "This request was not found in your account."),
        h("p", {}, "Check that you signed in with the passkey of the account your agent uses."),
      ),
    );
    return;
  }
  const request = await host.ok<RequestRecord>(res);
  let meta: RequestMeta;
  try {
    meta = await openRequestMeta(keys, id, b64Decode(request.meta_ct)!);
  } catch {
    throw new Error("This request cannot be read with your vault key.");
  }

  const block = h("section", { class: "block" }, h("h3", {}, "> your agent asks for a secret"), h("p", { class: "ink" }, "The agent never sees what you enter here."));
  body.append(block);
  block.append(
    h(
      "dl",
      { class: "facts" },
      h("dt", {}, "Secret"),
      h("dd", {}, h("code", {}, meta.name)),
      h("dt", {}, "Agent says it is for"),
      h("dd", {}, meta.description),
      h("dt", {}, meta.fields.length > 1 ? "Fields" : "Field"),
      h("dd", {}, ...meta.fields.flatMap((f, i) => [i > 0 && " ", f === "" ? h("span", { class: "muted" }, "default") : h("code", {}, f)])),
      h("dt", {}, "Environment"),
      h("dd", {}, meta.env === "" ? h("span", { class: "muted" }, "any") : h("code", {}, meta.env)),
      h("dt", {}, "Context"),
      h("dd", {}, meta.context === "" ? h("span", { class: "muted" }, "any") : h("code", {}, meta.context)),
    ),
  );

  if (request.status !== "pending") {
    const text: Record<string, string> = {
      fulfilled: "This request was answered and the value is stored in your vault. It is not shown here.",
      declined: "This request was declined. Nothing was stored.",
      expired: "This request expired. Requests last 24 hours; ask your agent to request it again.",
    };
    block.append(h("p", { class: "ink" }, text[request.status] ?? `Status: ${request.status}`));
    return;
  }

  const key = lookupKey(meta.env, meta.context);
  for (const field of meta.fields) {
    const invalid = validateWrite(meta.name, { id: newId(), recordedAt: 0n, op: "set", field, key, value: "" });
    if (invalid) throw new Error(`The agent's request cannot be stored: ${invalid}`);
  }

  const stored = new Map<string, Revision[]>();
  let cursor = await pull(host, keys, meta.name, 0, stored);
  const now = current(entryOf(stored, meta.name).revisions);
  const exists = (field: string) => [...now.values.values()].some((v) => foldKey(v.field) === foldKey(field) && foldKey(v.key) === foldKey(key));

  // One value input per field. A secret value is not a login: keep password managers from filling it or offering to save it.
  const inputs = meta.fields.map((field, i) => {
    const single = h("input", { id: `f-value-${i}`, type: "password", autocomplete: "off", spellcheck: false, ...notALogin });
    const multi = h("textarea", { id: `f-value-multi-${i}`, rows: 6, autocomplete: "off", spellcheck: false, autocapitalize: "off", hidden: true, ...notALogin });
    const multiToggle = h("input", { id: `f-multiline-${i}`, type: "checkbox" });
    multiToggle.addEventListener("change", () => {
      const [from, to] = multiToggle.checked ? [single, multi] : [multi, single];
      to.value = from.value;
      from.value = "";
      from.hidden = true;
      to.hidden = false;
      to.focus();
    });
    const group = h(
      "div",
      { class: "f" },
      h("label", { htmlFor: single.id }, meta.fields.length > 1 ? (field === "" ? "Value (default field)" : field) : "Value"),
      single,
      multi,
      h("label", { class: "check", htmlFor: multiToggle.id }, multiToggle, " Multi-line value (shown as typed)"),
      exists(field)
        ? h("p", { class: "hint" }, "A value is stored for this field already. A new value replaces the current one; earlier values stay in history.")
        : h("p", { class: "hint" }, "No value is stored for this field yet."),
    );
    return { group, value: () => (multiToggle.checked ? multi.value : single.value), focus: () => (multiToggle.checked ? multi : single).focus(), clear: () => ((single.value = ""), (multi.value = "")) };
  });
  const label = meta.fields.length > 1 ? "store values" : exists(meta.fields[0]) ? "replace value" : "store value";
  const store = h("button", { class: "tbtn tbtn-primary tbtn-big", type: "submit" }, h("kbd", {}, "⏎"), label);
  const decline = h("button", { class: "tbtn", type: "button" }, "decline");
  const form = h("form", notALogin, ...inputs.map((x) => x.group), h("div", { class: "row-actions" }, store, decline));

  const finish = (text: string) => {
    for (const x of inputs) x.clear();
    host.done(text, "ok");
  };

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    store.disabled = decline.disabled = true;
    try {
      const empty = inputs.find((x) => x.value() === "");
      if (empty) {
        empty.focus();
        throw new Error("Enter a value, or decline the request.");
      }
      out.set("Storing …");
      // Other writers may have been faster since the page was loaded: the Append rule needs the entry as it is now.
      cursor = await pull(host, keys, meta.name, cursor, stored);
      await fulfill(host, keys, id, meta, stored, inputs.map((x) => x.value()));
      finish(`Stored. Your agent can read "${meta.name}" now.`);
    } catch (err) {
      if (err instanceof SessionLost) await retry();
      else out.set(host.messageOf(err), "error");
      store.disabled = decline.disabled = false;
    }
  });

  decline.addEventListener("click", async () => {
    store.disabled = decline.disabled = true;
    try {
      const res = await host.api("POST", `/api/v1/requests/${id}/decline`);
      if (res.status === 401) throw new SessionLost();
      await host.ok(res);
      finish("Declined. Nothing was stored, and your agent was told.");
    } catch (err) {
      if (err instanceof SessionLost) await retry();
      else out.set(host.messageOf(err), "error");
      store.disabled = decline.disabled = false;
    }
  });

  block.append(form);
  body.append(h("p", { class: "note" }, "The text above comes from your agent, not from Hort. Enter a value only if you expect this request."));
}

// Answers request `id` in one write: a set revision per requested field, in
// the order of meta.fields, on the entry and key the request folds to in the
// spelling they already have (Append rule against `stored`, which the caller
// has just pulled), then a describe revision when the description is missing
// or differs. Nothing is sent when a revision breaks the write rules.
export async function fulfill(host: Pick<Host, "api" | "ok">, keys: AccountKeys, id: string, meta: RequestMeta, stored: Map<string, Revision[]>, values: string[]): Promise<void> {
  const key = lookupKey(meta.env, meta.context);
  const { name, revisions: entry } = entryOf(stored, meta.name);
  const known = [...entry];
  meta.fields.forEach((field, i) => known.push({ id: newId(), recordedAt: appendStamp(known, nowNs()), op: "set", ...spelling(known, field, key), value: values[i] }));
  if (meta.description !== "" && current(entry).description !== meta.description) {
    known.push({ id: newId(), recordedAt: appendStamp(known, nowNs()), op: "describe", field: "", key: "", value: meta.description });
  }
  const sealed: { id: string; ct: string }[] = [];
  for (const r of known.slice(entry.length)) {
    const problem = validateWrite(name, r);
    if (problem) throw new Error(problem);
    sealed.push({ id: r.id, ct: b64Encode(await sealRevision(keys, name, r)) });
  }
  const res = await host.api("POST", `/api/v1/requests/${id}/fulfill`, { body: JSON.stringify({ revisions: sealed }) });
  if (res.status === 401) throw new SessionLost();
  await host.ok(res);
}
