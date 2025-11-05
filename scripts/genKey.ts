import { buildBabyjub, buildEddsa } from "circomlibjs";
import { genBabyJubKeypair } from "../helpers/key.ts";
import { bytesToHex } from "@noble/hashes/utils";

async function main(): Promise<void> {
  const babyjub = await buildBabyjub();
  const eddsa = await buildEddsa();
  const F = babyjub.F;

  const { prv, pub } = genBabyJubKeypair(babyjub, eddsa);

  const pubHex = pub.map((x) => F.toObject(x).toString(16));
  const prvHex = bytesToHex(prv);

  console.log(
    `Private key: 0x${prvHex}\nPublic key: 0x${pubHex[0]} 0x${pubHex[1]}`,
  );
}

main();
