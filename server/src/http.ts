// Errors are an HTTP status plus one plain-text line (contract §4, §6.6).
export function fail(status: number, message: string, headers: Record<string, string> = {}): Response {
  return new Response(message + "\n", {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", ...headers },
  });
}

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// Strict JSON object decoding: valid UTF-8, an object, exactly the given keys.
export function parseObject(bytes: Uint8Array, keys: string[]): Record<string, unknown> | null {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    return null;
  }
  return asObject(value, keys);
}

export function asObject(value: unknown, keys: string[]): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const obj = value as Record<string, unknown>;
  const present = Object.keys(obj);
  if (present.length !== keys.length || !keys.every((k) => present.includes(k))) return null;
  return obj;
}
