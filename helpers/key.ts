import { webcrypto as nodeCrypto } from "node:crypto";
import { blake512 } from "@noble/hashes/blake1";
// @ts-ignore
import { Scalar } from "ffjavascript";
import { type BabyJub, type Eddsa } from "circomlibjs";

const crypto: Crypto = globalThis.crypto ?? (nodeCrypto as unknown as Crypto);

export function randomScalar(mod: bigint): bigint {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  x %= mod - 1n;
  return x + 1n;
}

export function prv2sk(prv: Uint8Array, eddsa: Eddsa): bigint {
  const sBuff = eddsa.pruneBuffer(blake512(prv));
  let s = Scalar.fromRprLE(sBuff, 0, 32);
  return Scalar.shr(s, 3);
}

export function genBabyJubKeypair(
  babyjub: BabyJub,
  eddsa: Eddsa,
): { prv: Uint8Array; sk: bigint; pub: [Uint8Array, Uint8Array] } {
  const prv = new Uint8Array(32);
  crypto.getRandomValues(prv);
  const sk = prv2sk(prv, eddsa);
  const pub = babyjub.mulPointEscalar(babyjub.Base8, sk);
  return { prv, sk, pub };
}
