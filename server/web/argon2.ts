// Argon2id from the vendored hash-wasm build (web/vendor/hash-wasm, pinned and
// hash-checked by scripts/build-web.mjs). RFC 9106, version 0x13, as
// golang.org/x/crypto/argon2 in the CLI.
import { argon2id as hashWasmArgon2id } from "./vendor/hash-wasm/argon2.umd.min.cjs";
import type { ArgonParams } from "./vault-core";

export function argon2id(password: Uint8Array, salt: Uint8Array, p: ArgonParams): Promise<Uint8Array> {
  return hashWasmArgon2id({
    password,
    salt,
    iterations: p.t,
    memorySize: p.m,
    parallelism: p.p,
    hashLength: 32,
    outputType: "binary",
  });
}
