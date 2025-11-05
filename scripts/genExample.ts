import { buildBabyjub, buildEddsa, buildPoseidon } from "circomlibjs";
import { mkdirSync, writeFileSync } from "fs";
import { toBytesBE32Buf } from "../helpers/utils.ts";
import { getMerkleRoot } from "../helpers/merkletree.ts";
import { genBabyJubKeypair } from "../helpers/key.ts";
import { bytesToHex } from "@noble/hashes/utils";

const CENSUS_DEPTH = 40;
const N_VOTERS = 3;

async function main(): Promise<void> {
  const babyjub = await buildBabyjub();
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();
  const F = poseidon.F;

  const census: bigint[] = [];

  mkdirSync("example", { recursive: true });

  for (let i = 0; i < N_VOTERS; i++) {
    const { prv, pub } = genBabyJubKeypair(babyjub, eddsa);
    const prvHex = "0x" + bytesToHex(prv);
    writeFileSync(`example/voter${i + 1}_prv.txt`, prvHex);
    census.push(
      F.toObject(
        poseidon([F.toObject(pub[0]), F.toObject(pub[1])]),
      ),
    );
  }

  writeFileSync(
    `example/coordinator_prv.txt`,
    "0x" + bytesToHex(genBabyJubKeypair(babyjub, eddsa).prv),
  );

  writeFileSync(
    "example/census.bin",
    Buffer.concat(census.map(toBytesBE32Buf)),
  );

  const root = await getMerkleRoot(CENSUS_DEPTH, census);
  writeFileSync("example/census_root.txt", "0x" + root.toString(16));

  console.log("Wrote example setup to example/ directory");
}

main();
