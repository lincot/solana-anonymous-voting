import { readFileSync } from "fs";
import { type Groth16Proof } from "snarkjs";
import { compressProof } from "./compressSolana.ts";

export { compressProof };

const FP =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const FQ =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const be32 = (n0: bigint) => {
  let n = ((n0 % FP) + FP) % FP;
  const out = Buffer.alloc(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
};

const serG2 = (Q: any) => {
  const x0 = BigInt(Q[0][0]);
  const x1 = BigInt(Q[0][1]);
  const y0 = BigInt(Q[1][0]);
  const y1 = BigInt(Q[1][1]);
  return Buffer.concat([be32(x1), be32(x0), be32(y1), be32(y0)]);
};

const serG1 = (P: any) =>
  Buffer.concat([be32(BigInt(P[0])), be32(BigInt(P[1]))]);

export const negateG1 = (a: string[]) => {
  const y = (FQ - BigInt(a[1])).toString();
  return [a[0], y, a[2]];
};

export const serProof = (proof: Groth16Proof, negate = true) => ({
  a: negate ? serG1(negateG1(proof.pi_a)) : serG1(proof.pi_a),
  b: serG2(proof.pi_b),
  c: serG1(proof.pi_c),
});

export function formatVk(jsonPath: string): string {
  const vk = JSON.parse(readFileSync(jsonPath, "utf8"));
  const alpha = serG1(vk.vk_alpha_1);
  const beta = serG2(vk.vk_beta_2);
  const gamma = serG2(vk.vk_gamma_2);
  const delta = serG2(vk.vk_delta_2);
  const ic = vk.IC.map(serG1);

  return `Groth16Verifyingkey {
    nr_pubinputs: ${vk.IC.length - 1},
    vk_alpha_g1: [${Array.from(alpha)}],
    vk_beta_g2: [${Array.from(beta)}],
    vk_gamme_g2: [${Array.from(gamma)}],
    vk_delta_g2: [${Array.from(delta)}],
    vk_ic: &[${ic.map((x: any) => "\n        [" + Array.from(x) + "]")}\n    ],
};`;
}

// export function writeProofBin(proof: any, path = "proof.bin") {
//   const pr = serProof(proof, false);
//   writeFileSync(path, Buffer.concat([pr.a, pr.b, pr.c]));
// }

// export function writeVkBin(
//   jsonPath = "./build/Vote/groth16_vkey.json",
//   out = "vk.bin",
// ) {
//   const vk = JSON.parse(readFileSync(jsonPath, "utf8"));
//   const alpha = serG1(vk.vk_alpha_1);
//   const beta = serG2(vk.vk_beta_2);
//   const gamma = serG2(vk.vk_gamma_2);
//   const delta = serG2(vk.vk_delta_2);

//   const IC: any[] = vk.IC;
//   const icLen = Buffer.alloc(4);
//   icLen.writeUInt32BE(IC.length);

//   const parts = [
//     alpha,
//     Buffer.alloc(64),
//     beta,
//     gamma,
//     Buffer.alloc(64),
//     delta,
//     icLen,
//   ];
//   for (const P of IC) parts.push(serG1(P));
//   writeFileSync(out, Buffer.concat(parts));
// }

// export function writePublicInputsBin(
//   publicSignals: (string | bigint)[],
//   path = "public_inputs.bin",
// ) {
//   const bufs = publicSignals.map((s) => be32(BigInt(s)));
//   writeFileSync(path, Buffer.concat(bufs));
// }
