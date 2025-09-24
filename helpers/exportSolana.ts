import { readFileSync } from "fs";
import { type Groth16Proof } from "snarkjs";

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

function gtFp(a: bigint, b: bigint): boolean {
  return a > b;
}

function lexLargestFp2(y0: bigint, y1: bigint): boolean {
  const ny0 = (FP - ((y0 % FP) + FP) % FP) % FP;
  const ny1 = (FP - ((y1 % FP) + FP) % FP) % FP;
  if (y1 !== ny1) return gtFp(y1, ny1);
  return gtFp(y0, ny0);
}

function compressG1(xStr: string, yStr: string): Uint8Array {
  const x = BigInt(xStr);
  const y = BigInt(yStr);
  const sign = gtFp(((y % FP) + FP) % FP, (FP - ((y % FP) + FP) % FP) % FP);
  const out = be32(x);
  if (sign) out[0] |= 0x80;
  else out[0] &= 0x7f;
  return out;
}

function compressG2(
  x: [string, string],
  y: [string, string],
): Uint8Array {
  const x0 = BigInt(x[0]), x1 = BigInt(x[1]);
  const y0 = BigInt(y[0]), y1 = BigInt(y[1]);

  const sign = lexLargestFp2(y1, y0);
  const out0 = be32(x0);
  const out1 = be32(x1);
  if (sign) out0[0] |= 0x80;
  else out0[0] &= 0x7f;

  const out = new Uint8Array(64);
  out.set(out0, 0);
  out.set(out1, 32);
  return out;
}

export function compressProofForSolana(proof: {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
}) {
  const negA = negateG1(proof.pi_a);
  const a = compressG1(negA[0], negA[1]);
  const c = compressG1(proof.pi_c[0], proof.pi_c[1]);

  const bx: [string, string] = [proof.pi_b[0][1], proof.pi_b[0][0]];
  const by: [string, string] = [proof.pi_b[1][1], proof.pi_b[1][0]];
  const b = compressG2(bx, by);

  return {
    a,
    b,
    c,
  };
}

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
