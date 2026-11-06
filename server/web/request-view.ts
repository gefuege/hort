// Hort web app: /r/<id>, the page for an agent's secret request (contract §7.3).
// The page decrypts the request's metadata, shows what is asked for and
// whether a value exists for that tuple (never the value), and stores the
// value the user types through POST /requests/{id}/fulfill. The vault key and
// everything decrypted here stay in memory; no innerHTML (Trusted Types).
import { b64Decode, b64Encode } from "../src/wire";
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
  status: () => StatusOut;
  messageOf: (err: unknown) => string;
  api: (method: string, path: string, o?: { body?: string }) => Promise<Response>;
  ok: <T>(res: Response) => Promise<T>;
  // Keys of the unlocked vault when there is a passkey session as well, else null.
  keys: () => AccountKeys | null;
  // The server no longer accepts the session.
  sessionLost: () => void;
  // Renders passkey sign-in (and unlock) into `into`; `done` runs once the vault is unlocked.
  login: (into: HTMLElement, done: () => void) => void;
};

export const REQUEST_PATH = /^\/r\/([0-9a-f]{32})$/;

class SessionLost extends Error {}

type RequestRecord = { status: string; meta_ct: string; revision_ids: string[] };

export async function requestView(main: HTMLElement, host: Host, path: string): Promise<void> {
  const id = REQUEST_PATH.exec(path)![1];
  const body = host.h("div");
  main.append(body);
  const show = async (): Promise<void> => {
    body.replaceChildren();
    try {
      await load(body, host, id, show);
    } catch (err) {
      if (!(err instanceof SessionLost)) {
        body.append(host.h("p", { class: "status status-error", role: "status" }, host.messageOf(err)));
        return;
      }
      host.sessionLost();
      body.replaceChildren(
        host.h("p", { class: "sec-intro" }, "Your agent asked for a secret. Sign in with your passkey to see the request and answer it."),
      );
      const slot = host.h("div");
      body.append(slot);
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

async function load(body: HTMLElement, host: Host, id: string, retry: () => Promise<void>): Promise<void> {
  const { h } = host;
  const keys = host.keys();
  if (!keys) throw new SessionLost();

  const res = await get(host, `/api/v1/requests/${id}`);
  if (res.status === 404) {
    body.append(
      h("p", { class: "sec-intro" }, "This request was not found in your account."),
      h("p", { class: "muted" }, "Check that you signed in with the passkey of the account your agent uses."),
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

  body.append(
    h("p", { class: "sec-intro" }, "Your agent asks you for a secret. The agent never sees what you enter here."),
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
    body.append(h("section", { class: "panel" }, h("h2", { class: "panel-h" }, request.status), h("p", {}, text[request.status] ?? `Status: ${request.status}`)));
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

  const out = host.status();
  const single = h("input", { id: "f-value", type: "password", autocomplete: "off", spellcheck: false });
  const multi = h("textarea", { id: "f-value-multi", rows: 6, autocomplete: "off", spellcheck: false, autocapitalize: "off", hidden: true });
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
  const store = h("button", { class: "btn btn-primary", type: "submit" }, exists ? "Replace value" : "Store value");
  const decline = h("button", { class: "btn btn-ghost", type: "button" }, "Decline");
  const form = h(
    "form",
    { class: "form" },
    h(
      "div",
      { class: "field" },
      h("label", { htmlFor: "f-value" }, "Value"),
      single,
      multi,
      h("label", { class: "check", htmlFor: "f-multiline" }, multiToggle, " Multi-line value (shown as typed)"),
      exists
        ? h("p", { class: "hint" }, "A value is stored for this secret already. A new value replaces the current one; earlier values stay in history.")
        : h("p", { class: "hint" }, "No value is stored for this secret yet."),
    ),
    h("div", { class: "actions" }, store, decline),
    out.el,
  );

  const finish = (text: string) => {
    single.value = "";
    multi.value = "";
    form.replaceWith(h("section", { class: "panel" }, h("h2", { class: "panel-h" }, "Done"), h("p", {}, text)));
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
      finish(`Stored. Your agent can read "${meta.name}" now. You can close this page.`);
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

  body.append(
    h("section", { class: "panel" }, h("h2", { class: "panel-h" }, "Your answer"), form),
    h("p", { class: "aside-note" }, "The text above comes from your agent, not from Hort. Enter a value only if you expect this request."),
  );
}
