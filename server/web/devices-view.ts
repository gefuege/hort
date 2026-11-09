// /devices: the devices and passkeys of the account in the console, with an
// inline revoke. GET /devices moves the server's visit time to now, so the
// view loads the listing once and marks revoked rows in place.
import { formatTime } from "./format-time";

type Child = Node | string | null | false | undefined;

export type Host = {
  h: <K extends keyof HTMLElementTagNameMap>(tag: K, props?: Record<string, unknown>, ...children: Child[]) => HTMLElementTagNameMap[K];
  messageOf: (err: unknown) => string;
  api: (method: string, path: string, o?: { body?: string }) => Promise<Response>;
  ok: <T>(res: Response) => Promise<T>;
  // The server refused the session: renders passkey sign-in into `into`.
  login: (into: HTMLElement) => void;
};

type Item = { id: string; created_at: number; revoked_at: number | null };
type Device = Item & { name: string; last_seen_at: number | null };
type Passkey = Item & { prf: boolean; last_used_at: number | null };
export type Listing = { devices: Device[]; passkeys: Passkey[]; last_visit_at?: number | null };

const time = (t: number | null) => (t === null ? "never" : formatTime(t * 1000));

// What changed since the previous visit of this account's sessions.
export function notices(list: Listing): string[] {
  const since = list.last_visit_at ?? null;
  if (since === null) return [];
  const out: string[] = [];
  for (const d of list.devices) {
    if (d.created_at > since) out.push(`new device “${d.name}” enrolled ${time(d.created_at)}`);
    if (d.revoked_at !== null && d.revoked_at > since) out.push(`device “${d.name}” revoked ${time(d.revoked_at)}`);
  }
  for (const p of list.passkeys) {
    if (p.created_at > since) out.push(`new passkey ${p.id.slice(0, 8)} added ${time(p.created_at)}`);
    if (p.revoked_at !== null && p.revoked_at > since) out.push(`passkey ${p.id.slice(0, 8)} revoked ${time(p.revoked_at)}`);
  }
  return out;
}

type Row = { kind: "device" | "passkey"; item: Device | Passkey; label: string; cells: string[] };

export async function devicesView(body: HTMLElement, host: Host): Promise<void> {
  const { h } = host;
  body.append(h("p", { class: "v-status status", role: "status" }, "Loading devices …"));
  const res = await host.api("GET", "/api/v1/devices");
  if (!body.isConnected) return;
  if (res.status === 401 || res.status === 409) {
    body.replaceChildren();
    host.login(body);
    return;
  }
  const list = await host.ok<Listing>(res);
  if (!body.isConnected) return;

  const all: Row[] = [
    ...list.devices.map((d): Row => ({ kind: "device", item: d, label: `device “${d.name}”`, cells: [d.name, time(d.created_at), time(d.last_seen_at)] })),
    ...list.passkeys.map((p): Row => ({ kind: "passkey", item: p, label: `passkey ${p.id.slice(0, 8)}`, cells: [p.id.slice(0, 8), p.prf ? "yes" : "no", time(p.created_at), time(p.last_used_at)] })),
  ];
  let shown: Row[] = [];
  let selected: Row | null = null;
  let confirming: Row | null = null;
  let busy = false;

  const filter = h("input", { id: "devices-filter", type: "search", placeholder: "filter devices and passkeys …", autocomplete: "off", spellcheck: false, "aria-label": "Filter devices and passkeys" });
  const groups = h("div", {});
  const statusLine = h("p", { class: "v-status status", role: "status", "aria-live": "polite" });
  const say = (text: string, kind?: "error" | "ok") => {
    statusLine.textContent = text;
    statusLine.className = `v-status status${kind ? ` status-${kind}` : ""}`;
  };
  const changes = notices(list);
  const root = h(
    "div",
    { class: "console-view" },
    h("div", { class: "prompt" }, h("label", { class: "ps1", htmlFor: filter.id }, "> ", h("span", { class: "cmd" }, "hort devices")), filter),
    changes.length ? h("div", { class: "notice", role: "note" }, h("p", {}, `Since your last visit: ${changes.join("; ")}.`)) : null,
    groups,
    h(
      "p",
      { class: "note" },
      "Revoking ends server access for that device or passkey. It does not protect against anyone who already holds your vault key; in that case create a new account and change the exposed secrets where they were issued.",
    ),
    h(
      "div",
      { class: "foot" },
      statusLine,
      h("div", { class: "hints", "aria-label": "Keyboard shortcuts" }, ...[["/", "filter"], ["↑ ↓", "select"], ["d", "revoke"], ["esc", "close"], ["g v·d·a", "switch"], ["?", "help"]].map(([k, what]) => h("span", {}, h("kbd", {}, k), what))),
    ),
  );
  const active = () => root.isConnected;

  function rowEl(r: Row, tabbable: boolean): HTMLLIElement {
    const li = h("li", { class: `v-row${r === selected ? " sel" : ""}`, tabIndex: tabbable ? 0 : -1, "aria-label": r.label });
    const labels = r.kind === "device" ? ["", "added", "seen"] : ["", "unlocks vault", "added", "used"];
    li.append(h("span", { class: "key" }, ...r.cells.map((c, i) => h("span", i === 0 ? { class: "c-name" } : { class: "c-m", "data-l": labels[i] }, c))));
    if (confirming === r) {
      const no = h("button", { class: "no", type: "button", onclick: () => closeConfirm() }, h("u", {}, "n"), " keep");
      const yes = h("button", { class: "yes", type: "button", onclick: () => void revoke(r) }, h("u", {}, "y"), " revoke");
      li.append(h("span", { class: "confirm" }, h("span", { class: "q" }, `revoke ${r.label}? It loses access to this account's server.`), no, yes));
    } else if (r.item.revoked_at !== null) {
      li.append(h("span", { class: "c-state revoked" }, `revoked ${time(r.item.revoked_at)}`));
    } else {
      li.append(
        h("span", { class: "c-state" }, "active"),
        h("span", { class: "act" }, h("button", { class: "danger", type: "button", onclick: () => askRevoke(r) }, h("u", {}, "d"), " revoke")),
      );
    }
    li.addEventListener("click", (e) => {
      if (!(e.target as Element).closest("button") && selected !== r) select(r);
    });
    li.addEventListener("focus", () => {
      if (selected === r || confirming) return;
      selected = r;
      for (const x of groups.querySelectorAll(".v-row.sel")) x.classList.remove("sel");
      li.classList.add("sel");
    });
    return li;
  }

  function group(kind: Row["kind"], cols: string[], empty: Child[]): HTMLElement[] {
    const rows = shown.filter((r) => r.kind === kind);
    const activeCount = all.filter((r) => r.kind === kind && r.item.revoked_at === null).length;
    const tabbable = selected ?? shown[0];
    return [
      h("p", { class: "group-h" }, `// ${kind === "device" ? "devices" : "passkeys"} · ${activeCount} active`),
      h("div", { class: `v-cols ${kind === "device" ? "d-cols" : "p-cols"}`, "aria-hidden": "true" }, ...cols.map((c) => h("span", {}, c))),
      h(
        "ul",
        { class: `v-list ${kind === "device" ? "d-list" : "p-list"}`, "aria-label": kind === "device" ? "Devices" : "Passkeys" },
        ...(rows.length ? rows.map((r) => rowEl(r, r === tabbable)) : [h("li", { class: "empty" }, h("p", {}, ...empty))]),
      ),
    ];
  }

  function draw(): void {
    const terms = filter.value.toLowerCase().split(/\s+/).filter(Boolean);
    shown = all.filter((r) => terms.every((t) => [r.kind, ...r.cells].join(" ").toLowerCase().includes(t)));
    if (selected && !shown.includes(selected)) selected = null;
    const none = filter.value.trim() ? ["Nothing matches."] : null;
    groups.replaceChildren(
      ...group("device", ["name", "added", "last seen", "state"], none ?? ["No devices. Run ", h("code", {}, "hort init"), " on a computer to add one."]),
      ...group("passkey", ["passkey", "unlocks vault", "added", "last used", "state"], none ?? ["No passkeys. Add one under access (", h("code", {}, "g a"), ")."]),
    );
  }

  const focusSelected = () => groups.querySelector<HTMLElement>(".v-row.sel")?.focus();
  function select(r: Row | null): void {
    selected = r;
    confirming = null;
    draw();
    focusSelected();
  }
  function askRevoke(r: Row): void {
    if (r.item.revoked_at !== null) return;
    selected = r;
    confirming = r;
    draw();
    groups.querySelector<HTMLElement>(".confirm .no")?.focus();
  }
  function closeConfirm(): void {
    confirming = null;
    draw();
    focusSelected();
  }
  async function revoke(r: Row): Promise<void> {
    if (busy) return;
    busy = true;
    try {
      await host.ok(await host.api("DELETE", `/api/v1/devices/${r.item.id}`));
      if (!active()) return;
      r.item.revoked_at = Math.floor(Date.now() / 1000);
      confirming = null;
      draw();
      focusSelected();
      say(`Revoked ${r.label}.`, "ok");
    } catch (err) {
      if (active()) say(host.messageOf(err), "error");
    } finally {
      busy = false;
    }
  }

  function onKey(e: KeyboardEvent): void {
    if (!active()) return document.removeEventListener("keydown", onKey);
    if (e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented) return;
    const t = e.target as HTMLElement;
    if (t !== document.body && !root.contains(t)) return;
    const i = selected ? shown.indexOf(selected) : -1;
    const key = e.key;
    if (t === filter) {
      if (key === "Escape") filter.value ? ((filter.value = ""), draw()) : filter.blur();
      else if ((key === "ArrowDown" || key === "Enter") && shown[0]) select(shown[0]);
      else return;
      return e.preventDefault();
    }
    if (confirming) {
      if (key === "y") void revoke(confirming);
      else if (key === "n" || key === "Escape") closeConfirm();
      else return;
      return e.preventDefault();
    }
    if (key === "Enter" && t.closest("button")) return;
    if (key === "/") (filter.focus(), filter.select());
    else if (key === "ArrowDown" && shown.length) select(shown[Math.min(i + 1, shown.length - 1)]);
    else if (key === "ArrowUp") i <= 0 ? filter.focus() : select(shown[i - 1]);
    else if (key === "d" && selected) askRevoke(selected);
    else if (key === "Escape" && selected) select(null);
    else return;
    e.preventDefault();
  }

  filter.addEventListener("input", () => {
    selected = null;
    confirming = null;
    draw();
  });
  document.addEventListener("keydown", onKey);
  body.replaceChildren(root);
  draw();
}
