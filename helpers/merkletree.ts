import { buildPoseidon } from "circomlibjs";

// we could just use @zk-kit/imt I guess

export async function getMerkleRoot(
  depth: number,
  leafs: bigint[],
) {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const def: bigint[] = new Array(depth + 1);
  def[0] = F.toObject(poseidon([0n]));
  for (let i = 1; i <= depth; i++) {
    def[i] = F.toObject(poseidon([def[i - 1], def[i - 1]]));
  }

  let cur = leafs[0];

  let level = leafs.slice();

  for (let lvl = 0; lvl < depth; lvl++) {
    const sib = 1 < level.length ? level[1] : def[lvl];
    cur = F.toObject(poseidon([cur, sib]));

    const newLevelLen = (level.length + 1) >> 1;
    for (let j = 0; j < newLevelLen; j++) {
      const sibIndex = 2 * j + 1;
      const sib = sibIndex < level.length ? level[sibIndex] : def[lvl];
      level[j] = F.toObject(poseidon([level[2 * j], sib]));
    }
    level = level.slice(0, newLevelLen);
  }

  return cur;
}

export async function getMerkleProof(
  depth: number,
  leafs: bigint[],
  index: number,
) {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const def: bigint[] = new Array(depth + 1);
  def[0] = F.toObject(poseidon([0n]));
  for (let i = 1; i <= depth; i++) {
    def[i] = F.toObject(poseidon([def[i - 1], def[i - 1]]));
  }

  const path: bigint[] = new Array(depth);
  const pathPos: bigint[] = new Array(depth);
  let cur = leafs[index];
  let idx = index;

  let level = leafs.slice();

  for (let lvl = 0; lvl < depth; lvl++) {
    const bit = idx & 1; // 0 = left, 1 = right
    pathPos[lvl] = BigInt(bit);
    const sibIndex = idx + (1 - 2 * bit); // 0 -> 1, 1 -> -1
    const sib = sibIndex < level.length ? level[sibIndex] : def[lvl];
    path[lvl] = sib;

    if (bit === 0) cur = F.toObject(poseidon([cur, sib]));
    else cur = F.toObject(poseidon([sib, cur]));
    idx >>= 1;

    const newLevelLen = (level.length + 1) >> 1;
    for (let j = 0; j < newLevelLen; j++) {
      const sibIndex = 2 * j + 1;
      const sib = sibIndex < level.length ? level[sibIndex] : def[lvl];
      level[j] = F.toObject(poseidon([level[2 * j], sib]));
    }
    level = level.slice(0, newLevelLen);
  }

  return { root: cur, path, pathPos };
}
