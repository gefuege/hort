// Hort web app: /r/<id>, the page for an agent's secret request (contract §7.3).
// The page decrypts the request's metadata, shows what is asked for and
// whether a value exists for that tuple (never the value), and stores the
// value the user types through POST /requests/{id}/fulfill. The vault key and
// everything decrypted here stay in memory; no innerHTML (Trusted Types).
import { b64Decode, b64Encode } from "../src/wire";
import { notALogin } from "./not-a-login";
import {
  appendStamp,
  current,
  lookupKey,
  newId,
  nowNs,
  openRequestMeta,
  openRevision,
  sealRevision,
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

// Pulls every revision after `after`, keeps those of the secret `name` and
// returns the new cursor. Envelopes that do not decrypt are skipped.
async function pull(host: Host, keys: AccountKeys, name: string, after: number, into: Revision[]): Promise<number> {
  let cursor = after;
  for (;;) {
    const page = await host.ok<{ revisions: { id: string; ct: string }[]; cursor: number; more: boolean }>(
      await get(host, `/api/v1/revisions?after=${cursor}&limit=500`),
    );
    for (const r of page.revisions) {
      try {
        const opened = await openRevision(keys, r.id, b64Decode(r.ct)!);
        if (opened.name === name) into.push(opened.revision);
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
      h("dt", {}, "Field"),
      h("dd", {}, meta.field === "" ? h("span", { class: "muted" }, "default") : h("code", {}, meta.field)),
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
  const invalid = validateWrite(meta.name, { id: newId(), recordedAt: 0n, op: "set", field: meta.field, key, value: "" });
  if (invalid) {
    throw new Error(`The agent's request cannot be stored: ${invalid}`);
  }

  const entry: Revision[] = [];
  let cursor = await pull(host, keys, meta.name, 0, entry);
  const now = current(entry);
  const exists = [...now.values.values()].some((v) => v.field === meta.field && v.key === key);

  // A secret value is not a login: keep password managers from filling it or offering to save it.
  const single = h("input", { id: "f-value", type: "password", autocomplete: "off", spellcheck: false, ...notALogin });
  const multi = h("textarea", { id: "f-value-multi", rows: 6, autocomplete: "off", spellcheck: false, autocapitalize: "off", hidden: true, ...notALogin });
  const multiToggle = h("input", { id: "f-multiline", type: "checkbox" });
  multiToggle.addEventListener("change", () => {
    const [from, to] = multiToggle.checked ? [single, multi] : [multi, single];
    to.value = from.value;
    from.value = "";
    from.hidden = true;
    to.hidden = false;
    to.focus();
  });
  const value = () => (multiToggle.checked ? multi.value : single.value);
  const store = h("button", { class: "tbtn tbtn-primary tbtn-big", type: "submit" }, h("kbd", {}, "⏎"), exists ? "replace value" : "store value");
  const decline = h("button", { class: "tbtn", type: "button" }, "decline");
  const form = h(
    "form",
    notALogin,
    h(
      "div",
      { class: "f" },
      h("label", { htmlFor: "f-value" }, "Value"),
      single,
      multi,
      h("label", { class: "check", htmlFor: "f-multiline" }, multiToggle, " Multi-line value (shown as typed)"),
      exists
        ? h("p", { class: "hint" }, "A value is stored for this secret already. A new value replaces the current one; earlier values stay in history.")
        : h("p", { class: "hint" }, "No value is stored for this secret yet."),
    ),
    h("div", { class: "row-actions" }, store, decline),
  );

  const finish = (text: string) => {
    single.value = "";
    multi.value = "";
    host.done(text, "ok");
  };

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    store.disabled = decline.disabled = true;
    try {
      if (value() === "") throw new Error("Enter a value, or decline the request.");
      out.set("Storing …");
      // Other writers may have been faster since the page was loaded: the Append rule needs the entry as it is now.
      cursor = await pull(host, keys, meta.name, cursor, entry);
      const set: Revision = { id: newId(), recordedAt: appendStamp(entry, nowNs()), op: "set", field: meta.field, key, value: value() };
      const revisions = [set];
      if (meta.description !== "" && current(entry).description !== meta.description) {
        revisions.push({ id: newId(), recordedAt: appendStamp([...entry, set], nowNs()), op: "describe", field: "", key: "", value: meta.description });
      }
      const sealed: { id: string; ct: string }[] = [];
      for (const r of revisions) {
        const problem = validateWrite(meta.name, r);
        if (problem) throw new Error(problem);
        sealed.push({ id: r.id, ct: b64Encode(await sealRevision(keys, meta.name, r)) });
      }
      const res = await host.api("POST", `/api/v1/requests/${id}/fulfill`, { body: JSON.stringify({ revisions: sealed }) });
      if (res.status === 401) throw new SessionLost();
      await host.ok(res);
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
