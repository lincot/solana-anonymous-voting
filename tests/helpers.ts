import { webcrypto as nodeCrypto } from "node:crypto";

const crypto: Crypto = globalThis.crypto ?? (nodeCrypto as unknown as Crypto);

export function randomScalar(mod: bigint): bigint {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  x %= mod - 1n;
  return x + 1n;
}

export async function genBabyJubKeypair(babyjub: any) {
  const sk = randomScalar(babyjub.subOrder);
  const pk = babyjub.mulPointEscalar(babyjub.Base8, sk);
  return { sk, PKx: pk[0], PKy: pk[1], babyjub };
}
