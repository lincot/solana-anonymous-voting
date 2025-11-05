const FP =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const FQ =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

function gtFp(a: bigint, b: bigint): boolean {
  return a > b;
}

const be32 = (n0: bigint) => {
  let n = ((n0 % FP) + FP) % FP;
  const out = Buffer.alloc(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
};

function compressG1(xStr: string, yStr: string): Uint8Array {
  const x = BigInt(xStr);
  const y = BigInt(yStr);
  const sign = gtFp(((y % FP) + FP) % FP, (FP - ((y % FP) + FP) % FP) % FP);
  const out = be32(x);
  if (sign) out[0] |= 0x80;
  else out[0] &= 0x7f;
  return out;
}

function lexLargestFp2(y0: bigint, y1: bigint): boolean {
  const ny0 = (FP - ((y0 % FP) + FP) % FP) % FP;
  const ny1 = (FP - ((y1 % FP) + FP) % FP) % FP;
  if (y1 !== ny1) return gtFp(y1, ny1);
  return gtFp(y0, ny0);
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

const negateG1 = (a: string[]) => {
  const y = (FQ - BigInt(a[1])).toString();
  return [a[0], y, a[2]];
};

export function compressProof(proof: {
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
