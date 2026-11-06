// Types for the one export Hort uses from hash-wasm 4.12.0 (dist/argon2.umd.min.js).
export function argon2id(options: {
  password: Uint8Array;
  salt: Uint8Array;
  iterations: number;
  memorySize: number;
  parallelism: number;
  hashLength: number;
  outputType: "binary";
}): Promise<Uint8Array>;
