import { DurableObject } from "cloudflare:workers";
import { fail, json } from "./http";
import { hexEncode, sha256 } from "./wire";

// Invitations (README "Invitations"): one instance for the whole server, so
// create, list, consume and revoke are each one atomic step. A code is 16
// random bytes as hex; only its SHA-256 is stored, and the code leaves the
// server once, in the answer to create. Revoking deletes an open invitation.
const SCHEMA = `
CREATE TABLE IF NOT EXISTS invitations (id TEXT PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL,
                                        used_at INTEGER, account_id TEXT);
`;

// One answer for unknown, used and revoked codes, here and in the Worker.
export const INVITE_INVALID = "this invitation is not valid or was already used; ask the person who invited you for a new invite link";

type InvitationRow = { id: string; created_at: number; used_at: number | null; account_id: string | null };

const now = () => Math.floor(Date.now() / 1000);

export class Invitations extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(SCHEMA);
  }

  private get sql() {
    return this.ctx.storage.sql;
  }

  async create(): Promise<Response> {
    const code = crypto.getRandomValues(new Uint8Array(16));
    const id = hexEncode(crypto.getRandomValues(new Uint8Array(4)));
    const hash = await sha256(code);
    this.sql.exec("INSERT INTO invitations (id, code_hash, created_at) VALUES (?, ?, ?)", id, hash, now());
    return json(201, { id, code: hexEncode(code) });
  }

  list(): Response {
    const invitations = this.sql
      .exec<InvitationRow>("SELECT id, created_at, used_at, account_id FROM invitations ORDER BY created_at, id")
      .toArray();
    return json(200, { invitations });
  }

  revoke(id: string): Response {
    const row = this.sql.exec<{ used_at: number | null }>("SELECT used_at FROM invitations WHERE id = ?", id).toArray()[0];
    if (!row) return fail(404, "invitation not found");
    if (row.used_at !== null) return fail(409, "invitation already used");
    this.sql.exec("DELETE FROM invitations WHERE id = ?", id);
    return json(200, { id });
  }

  // Spends the invitation with this code hash for account, once. The same
  // account may spend it again, so a retried registration still passes.
  consume(codeHash: Uint8Array, account: string): boolean {
    return (
      this.sql
        .exec(
          "UPDATE invitations SET used_at = coalesce(used_at, ?), account_id = ? WHERE code_hash = ? AND (account_id IS NULL OR account_id = ?) RETURNING id",
          now(), account, codeHash, account,
        )
        .toArray().length === 1
    );
  }
}

export const invitationsStub = (env: Env) => env.INVITATIONS.jurisdiction("eu").getByName("invitations");
