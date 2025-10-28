import { buildEddsa, buildPoseidon } from "circomlibjs";
import { randomBytes } from "crypto";
import { toBytesBE32Buf } from "../helpers/utils.ts";
import { bytes2Hex } from "@iden3/js-merkletree";

async function main(): Promise<void> {
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();
  const F = poseidon.F;

  const prvHex = "0x" + randomBytes(250).toString("hex");
  const prv = BigInt(prvHex);
  const pub = eddsa.prv2pub(F.e(prv));
  const pubHex = pub.map((x) => bytes2Hex(toBytesBE32Buf(F.toObject(x))));

  console.log(`Private key: ${prvHex}\nPub: 0x${pubHex[0]} 0x${pubHex[1]}`);
}

main();
