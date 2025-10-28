import { buildEddsa, buildPoseidon } from "circomlibjs";
import { mkdirSync, writeFileSync } from "fs";
import { randomBytes } from "crypto";
import { toBytesBE32Buf } from "../helpers/utils.ts";
import { getMerkleRoot } from "../helpers/merkletree.ts";

const CENSUS_DEPTH = 40;
const N_VOTERS = 3;

const genKey = (eddsa: any, F: any) => {
  const prvHex = "0x" + randomBytes(250).toString("hex");
  const prv = BigInt(prvHex);
  const pub = eddsa.prv2pub(F.e(prv));
  return { pub, prvHex };
};

async function main(): Promise<void> {
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();
  const F = poseidon.F;

  const census: bigint[] = [];

  mkdirSync("example", { recursive: true });

  for (let i = 0; i < N_VOTERS; i++) {
    const { pub, prvHex } = genKey(eddsa, F);
    writeFileSync(`example/voter${i + 1}_prv.txt`, prvHex);
    census.push(
      F.toObject(
        poseidon([F.toObject(pub[0]), F.toObject(pub[1])]),
      ),
    );
  }

  writeFileSync(`example/coordinator_prv.txt`, genKey(eddsa, F).prvHex);

  writeFileSync(
    "example/census.bin",
    Buffer.concat(census.map(toBytesBE32Buf)),
  );

  const root = await getMerkleRoot(CENSUS_DEPTH, census);
  writeFileSync("example/census_root.txt", "0x" + root.toString(16));

  console.log("Wrote example setup to example/ directory");
}

main();
