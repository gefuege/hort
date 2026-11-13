// Hort web app: /s/<id>, the page for a secret shared by link. It opens
// without an account: the recipient types their name, which with the link key
// from the URL fragment opens the share (share-core.ts). The link key never
// leaves this page: no request, log, storage or query string carries it.
// Values stay masked until Show; no innerHTML (Trusted Types). A request
// shows the values as masked inputs the recipient can change and send once.
import { b64Decode, b64Encode, b64urlDecode } from "../src/wire";
import { notALogin } from "./not-a-login";
import { deriveShareKeys, formatShareLink, normalizeShareName, openShare, sealShareAnswer, SHARE_LINK_KEY_BYTES, type SharedAnswer, type SharedSecret, type ShareKeys } from "./share-core";
import { current, entryOf, lookupKey } from "./vault-core";
import { CLIPBOARD_S, copy, pull, REVEAL_S, SignInRequired, write, type Change, type Unlocked } from "./vault-view";

type Child = Node | string | null | false | undefined;

// What the page needs from the app shell.
export type Host = {
  h: <K extends keyof HTMLElementTagNameMap>(tag: K, props?: Record<string, unknown>, ...children: Child[]) => HTMLElementTagNameMap[K];
  messageOf: (err: unknown) => string;
  api: (method: string, path: string, o?: { body?: string }) => Promise<Response>;
  ok: <T>(res: Response) => Promise<T>;
  // The unlocked vault when there is a passkey session as well, else null.
  unlocked: () => Unlocked | null;
  // The server no longer accepts the session.
  sessionLost: () => void;
};

export const SHARE_PATH = /^\/s\/([0-9a-f]{32})$/;
export const GONE = "This link no longer opens. Ask the sender for a new one.";
const DELETED = "Deleted. The link no longer opens, and the sender sees it was picked up.";
const DECLINED = "Deleted. The link no longer opens, and the sender sees you declined.";
const SENT = "Sent. The sender checks the values before using them. The link no longer opens.";

// A recipient call: no session, the access token alone.
export type Send = (method: "POST" | "DELETE", path: string, token: Uint8Array, body?: string) => Promise<Response>;
export const send: Send = (method, path, token, body) =>
  fetch(path, { method, headers: { "Hort-Share-Token": b64Encode(token) }, credentials: "omit", ...(body === undefined ? {} : { body }) });

export type Opened = { kind: "secret"; secret: SharedSecret; keys: ShareKeys } | { kind: "wrong"; triesLeft: number } | { kind: "gone" };

const failed = async (res: Response) => new Error((await res.text()).trim() || `request failed (${res.status})`);

// Opens share shareId for the name the recipient typed.
export async function openShared(call: Send, shareId: string, linkKey: Uint8Array, name: string): Promise<Opened> {
  const keys = await deriveShareKeys(name, linkKey, shareId);
  const res = await call("POST", `/api/v1/shares/${shareId}/open`, keys.token);
  if (res.status === 404) return { kind: "gone" };
  if (res.status === 403) return { kind: "wrong", triesLeft: ((await res.json()) as { tries_left: number }).tries_left };
  if (!res.ok) throw await failed(res);
  const { ct } = (await res.json()) as { ct: string };
  return { kind: "secret", secret: await openShare(keys, shareId, b64Decode(ct) ?? new Uint8Array()), keys };
}

// Sends the answer to request shareId once. False when it no longer opened.
export async function answerShared(call: Send, shareId: string, keys: ShareKeys, answer: SharedAnswer): Promise<boolean> {
  const ct = await sealShareAnswer(keys, shareId, answer);
  const res = await call("POST", `/api/v1/shares/${shareId}/answer`, keys.token, JSON.stringify({ ct: b64Encode(ct) }));
  if (res.status === 404) return false;
  if (!res.ok) throw await failed(res);
  return true;
}

// Deletes the share for everyone. False when it no longer opened anyway.
export async function deleteShared(call: Send, shareId: string, token: Uint8Array): Promise<boolean> {
  const res = await call("DELETE", `/api/v1/shares/${shareId}`, token);
  if (res.status === 404) return false;
  if (!res.ok) throw await failed(res);
  return true;
}

// Saves the shared fields as default values (any env and context) plus the
// description under `name`. An existing secret of that name, in any letter
// case, is refused;
// nothing is overwritten or merged.
export async function saveShared(host: Pick<Host, "api" | "ok">, u: Unlocked, name: string, s: SharedSecret): Promise<void> {
  const v = await pull(host, u);
  const existing = entryOf(v.entries, name);
  if (current(existing.revisions).visible) throw new Error(`Your vault has a secret named ${existing.name} already. Pick another name.`);
  const changes: Change[] = s.fields.map((f) => ({ op: "set", field: f.field, key: lookupKey("", ""), value: f.value }));
  if (s.description !== "") changes.push({ op: "describe", field: "", key: "", value: s.description });
  await write(host, u, name, changes);
}

const fieldCount = (n: number) => `${n} ${n === 1 ? "field" : "fields"}`;

export function shareView(main: HTMLElement, host: Host, path: string): void {
  const { h, messageOf } = host;
  const id = SHARE_PATH.exec(path)![1];
  const linkKey = b64urlDecode(location.hash.slice(1));
  const body = h("div");
  const line = h("p", { class: "v-status status", role: "status", "aria-live": "polite" });
  const say = (text: string, kind?: "error" | "ok") => {
    line.textContent = text;
    line.className = `v-status status${kind ? ` status-${kind}` : ""}`;
  };
  const root = h(
    "div",
    { class: "console-view" },
    h("div", { class: "prompt static" }, h("span", { class: "ps1" }, "> ", h("span", { class: "cmd" }, "hort take"))),
    body,
    h("div", { class: "foot" }, line),
  );
  main.append(root);

  const end = (title: string, text: string) => body.replaceChildren(h("section", { class: "block lead" }, h("h3", {}, title), h("p", { class: "ink" }, text)));
  if (!linkKey || linkKey.length !== SHARE_LINK_KEY_BYTES) return end("> link closed", GONE);

  const input = h("input", { id: "f-share-name", autocomplete: "off", spellcheck: false, autocapitalize: "off", ...notALogin });
  const openButton = h("button", { class: "tbtn tbtn-primary tbtn-big", type: "submit" }, h("kbd", {}, "⏎"), "open");
  const form = h(
    "form",
    notALogin,
    h("div", { class: "f" }, h("label", { htmlFor: input.id }, "Your name"), input, h("p", { class: "hint" }, "Five wrong names destroy the link.")),
    h("div", { class: "row-actions" }, openButton),
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (normalizeShareName(input.value) === "") return say("Type your name.", "error");
    openButton.disabled = true;
    say("Opening …");
    try {
      const opened = await openShared(send, id, linkKey, input.value);
      if (!root.isConnected) return;
      if (opened.kind === "gone") {
        say("");
        return end("> link closed", GONE);
      }
      if (opened.kind === "wrong") {
        say(`That's not who this is for. ${opened.triesLeft} ${opened.triesLeft === 1 ? "try" : "tries"} left.`, "error");
        return input.select();
      }
      say("");
      if (opened.secret.kind === "request") requestView(opened.secret, opened.keys);
      else secretView(opened.secret, opened.keys.token);
    } catch (err) {
      say(messageOf(err), "error");
    } finally {
      openButton.disabled = false;
    }
  });
  body.append(h("section", { class: "block lead" }, h("h3", {}, "> a shared secret"), h("p", { class: "ink" }, "Someone shared a secret with you. Who are you?"), form));
  input.focus();

  function copyButton(label: string, value: () => string, what: string): HTMLButtonElement {
    const b = h("button", { class: "tbtn", type: "button" }, label);
    b.addEventListener("click", async () => {
      try {
        await copy(value(), (done) => root.isConnected && say(done ? "Clipboard cleared." : "This browser kept it on the clipboard; Hort clears it on your next click or key press here.", done ? "ok" : "error"));
        say(`Copied ${what}. The clipboard clears in ${CLIPBOARD_S} s.`, "ok");
      } catch (err) {
        say(messageOf(err), "error");
      }
    });
    return b;
  }

  // Deletes the link for everyone after a confirm; `done` ends the page.
  function removeButton(label: string, token: Uint8Array, done: (deleted: boolean) => void): HTMLButtonElement {
    const remove = h("button", { class: "tbtn danger", type: "button" }, label);
    remove.addEventListener("click", async () => {
      if (!confirm("Delete for everyone?")) return;
      remove.disabled = true;
      try {
        done(await deleteShared(send, id, token));
        say("");
      } catch (err) {
        say(messageOf(err), "error");
        remove.disabled = false;
      }
    });
    return remove;
  }

  // A request: the values as masked, editable inputs, sent back once.
  function requestView(s: SharedSecret, keys: ShareKeys): void {
    const finish = (title: string, text: string) => {
      keys.token.fill(0);
      s.fields = [];
      end(title, text);
    };
    const facts = h("dl", { class: "facts" }, h("dt", {}, "Name"), h("dd", {}, h("code", {}, s.name)));
    if (s.description !== "") facts.append(h("dt", {}, "Description"), h("dd", {}, s.description));
    const cells = s.fields.map((f, i) => {
      const cell = h("textarea", { id: `f-answer-${i}`, class: "cell", rows: Math.max(1, f.value.split("\n").length), value: f.value, placeholder: "empty", autocomplete: "off", ...notALogin });
      cell.spellcheck = false;
      return cell;
    });
    const sendButton = h("button", { class: "tbtn tbtn-primary tbtn-big", type: "submit" }, h("kbd", {}, "⏎"), "send");
    const form = h(
      "form",
      notALogin,
      ...s.fields.map((f, i) => h("div", { class: "f masked" }, h("label", { htmlFor: cells[i].id }, f.field || "default"), cells[i])),
      h("p", { class: "hint" }, "Values stay hidden until you click into them."),
      h("div", { class: "row-actions" }, sendButton),
    );
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      sendButton.disabled = true;
      say("Sending …");
      try {
        const answer = { name: s.name, description: s.description, fields: s.fields.map((f, i) => ({ field: f.field, value: cells[i].value })) };
        if (await answerShared(send, id, keys, answer)) finish("> sent", SENT);
        else finish("> link closed", GONE);
        say("");
      } catch (err) {
        say(messageOf(err), "error");
        sendButton.disabled = false;
      }
    });
    const remove = removeButton("decline, delete the link", keys.token, (deleted) => (deleted ? finish("> deleted", DECLINED) : finish("> link closed", GONE)));
    body.replaceChildren(
      h(
        "section",
        { class: "block lead" },
        h("h3", {}, "> values asked of you"),
        facts,
        h("p", { class: "ink" }, "Fill in or correct the values and send them once. The sender checks them before using them."),
        form,
      ),
      h("section", { class: "block" }, h("div", { class: "row-actions" }, remove)),
    );
  }

  function secretView(s: SharedSecret, token: Uint8Array): void {
    const finish = (title: string, text: string) => {
      token.fill(0);
      s.fields = [];
      end(title, text);
    };
    const facts = h("dl", { class: "facts" }, h("dt", {}, "Name"), h("dd", {}, h("code", {}, s.name)));
    if (s.description !== "") facts.append(h("dt", {}, "Description"), h("dd", {}, s.description));
    for (const f of s.fields) {
      const value = h("span", { class: "muted" }, "••••••••");
      let timer: number | undefined;
      const hide = () => {
        window.clearTimeout(timer);
        value.className = "muted";
        value.textContent = "••••••••";
        show.textContent = "show";
      };
      const show = h("button", { class: "tbtn", type: "button" }, "show");
      show.addEventListener("click", () => {
        if (show.textContent === "hide") return hide();
        value.className = "c-val";
        value.textContent = f.value === "" ? "(empty)" : f.value;
        show.textContent = "hide";
        timer = window.setTimeout(hide, REVEAL_S * 1000);
      });
      const label = f.field || "default";
      facts.append(h("dt", { class: "raw" }, label), h("dd", {}, value, " ", show, copyButton("copy", () => f.value, label)));
    }

    const command = `hort take '${formatShareLink(location.origin, id, linkKey!)}'`;
    const keep = h(
      "section",
      { class: "block" },
      h("h3", {}, "> keep it"),
      h("p", { class: "ink" }, "Take it into your vault with the Hort CLI:"),
      h("div", { class: "prompt static" }, h("span", { class: "ps1" }, "$ ", h("span", { class: "cmd" }, command))),
      h("div", { class: "row-actions" }, copyButton("copy command", () => command, "the command")),
      h("p", {}, "No Hort yet? ", h("code", {}, "npm install -g @s16e/hort && hort init"), " installs it."),
    );

    const remove = removeButton("I have it, delete the link", token, (deleted) => (deleted ? finish("> deleted", DELETED) : finish("> link closed", GONE)));

    const u = host.unlocked();
    let save: HTMLElement | null = null;
    if (u) {
      const name = h("input", { id: "f-save-name", autocomplete: "off", spellcheck: false, value: s.name, ...notALogin });
      const saveButton = h("button", { class: "tbtn tbtn-primary", type: "submit" }, "save to my vault");
      save = h(
        "form",
        notALogin,
        h("div", { class: "f" }, h("label", { htmlFor: name.id }, "Save as"), name, h("p", { class: "hint" }, "A secret of that name in your vault is never overwritten.")),
        h("div", { class: "row-actions" }, saveButton),
      );
      const form = save;
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const as = name.value.trim();
        saveButton.disabled = true;
        say("Saving …");
        try {
          await saveShared(host, u, as, s);
        } catch (err) {
          if (err instanceof SignInRequired) {
            host.sessionLost();
            form.remove();
          }
          say(messageOf(err), "error");
          saveButton.disabled = false;
          return;
        }
        const saved = `Saved ${as} to your vault (${fieldCount(s.fields.length)}).`;
        try {
          if (await deleteShared(send, id, token)) finish("> saved", `${saved} The link no longer opens, and the sender sees it was picked up.`);
          else finish("> saved", `${saved} The link no longer opens.`);
          say("");
        } catch (err) {
          form.remove();
          say(`${saved} The link was not deleted (${messageOf(err)}); delete it below, or it stays open until it expires.`, "error");
        }
      });
    }

    body.replaceChildren(h("section", { class: "block lead" }, h("h3", {}, "> shared with you"), facts));
    if (save) body.append(h("section", { class: "block" }, h("h3", {}, "> save to my vault"), save));
    body.append(keep, h("section", { class: "block" }, h("div", { class: "row-actions" }, remove)));
  }
}
