import {
  type BlockhashWithExpiryBlockHeight,
  Connection,
  Keypair,
  PublicKey,
  sendAndConfirmTransaction,
  type Signer,
  SystemProgram,
  Transaction,
  TransactionMessage,
  type TransactionSignature,
  VersionedTransaction,
} from "@solana/web3.js";
import * as anchor from "@coral-xyz/anchor";
import { AnchorProvider } from "@coral-xyz/anchor";
import NodeWallet from "@coral-xyz/anchor/dist/cjs/nodewallet.js";
import { BN } from "bn.js";

export function setupTests(): { provider: AnchorProvider; payer: Keypair } {
  const provider = AnchorProvider.env();
  anchor.setProvider(provider);
  const payer = (provider.wallet as NodeWallet).payer;
  return { provider, payer };
}

export async function disperse(
  connection: Connection,
  toPubkeys: PublicKey[],
  fromKeypair: Keypair,
  amount: number,
): Promise<void> {
  const tx = new Transaction();
  for (const toPubkey of toPubkeys) {
    tx.add(
      SystemProgram.transfer({
        fromPubkey: fromKeypair.publicKey,
        lamports: amount,
        toPubkey,
      }),
    );
  }
  await sendAndConfirmTransaction(connection, tx, [fromKeypair]);
}

export async function transfer(
  connection: Connection,
  from: Keypair,
  to: PublicKey,
  lamports: number,
): Promise<void> {
  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: from.publicKey,
        toPubkey: to,
        lamports,
      }),
    ),
    [from],
  );
}

export async function sendAndConfirmVersionedTx(
  connection: Connection,
  tx: Transaction,
  signers: Signer[],
  payerKey: PublicKey,
): Promise<TransactionSignature> {
  const { verTx, latestBlockhash } = await toVersionedTx(
    connection,
    tx,
    payerKey,
  );
  verTx.sign(signers);

  const transactionSignature = await connection
    .sendTransaction(verTx);

  await connection.confirmTransaction({
    blockhash: latestBlockhash.blockhash,
    lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
    signature: transactionSignature,
  });

  return transactionSignature;
}

async function toVersionedTx(
  connection: Connection,
  tx: Transaction,
  payerKey: PublicKey,
): Promise<
  {
    verTx: VersionedTransaction;
    latestBlockhash: BlockhashWithExpiryBlockHeight;
  }
> {
  const latestBlockhash = await connection.getLatestBlockhash();
  const messageV0 = new TransactionMessage({
    payerKey,
    recentBlockhash: latestBlockhash.blockhash,
    instructions: tx.instructions,
  }).compileToV0Message();

  return {
    verTx: new VersionedTransaction(messageV0),
    latestBlockhash,
  };
}

export const toBigint = (value: BN | bigint): bigint =>
  typeof value === "bigint"
    ? value
    : BigInt("0x" + (value as BN).toString("hex"));

const FP =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function toBytesBE32Buf(n0: bigint): Buffer {
  let n = ((n0 % FP) + FP) % FP;
  const out = Buffer.alloc(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

export function toBytesBE32(n0: bigint): Array<number> {
  return Array.from(toBytesBE32Buf(n0));
}

export const hexToBytes32 = (hex: string): Uint8Array => {
  let s = hex.replace(/^0x/i, "");
  if (s.length > 64) {
    throw new Error("Hex too long (max 64 nibbles = 32 bytes).");
  }
  if (!/^[0-9a-fA-F]*$/.test(s)) throw new Error("Invalid hex string.");
  if (s.length % 2 === 1) s = "0" + s;
  s = s.padStart(64, "0");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

const TA_TAG = "__typedarray__";
const BIGINT_TAG = "__bigint__";

const u8ToB64 = (u8: Uint8Array) =>
  typeof Buffer !== "undefined"
    ? Buffer.from(u8).toString("base64")
    : btoa(String.fromCharCode(...u8));

const b64ToU8 = (b64: string) =>
  typeof Buffer !== "undefined"
    ? new Uint8Array(Buffer.from(b64, "base64"))
    : new Uint8Array([...atob(b64)].map((c) => c.charCodeAt(0)));

const constructors: Record<string, any> = {
  Uint8Array,
  Int8Array,
  Uint16Array,
  Int16Array,
  Uint32Array,
  Int32Array,
  Float32Array,
  Float64Array,
  BigInt64Array,
  BigUint64Array,
};

export function replacer(_k: string, v: any) {
  if (typeof v === "bigint") return { [BIGINT_TAG]: v.toString() };

  if (ArrayBuffer.isView(v) && !(v instanceof DataView)) {
    const bytes = new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
    return { [TA_TAG]: v.constructor.name, data: u8ToB64(bytes) };
  }
  return v;
}

export function reviver(_k: string, v: any) {
  if (v && typeof v === "object") {
    if (BIGINT_TAG in v) return BigInt(v[BIGINT_TAG]);
    if (TA_TAG in v && typeof v.data === "string") {
      const ctor = constructors[v[TA_TAG]];
      if (ctor) {
        const bytes = b64ToU8(v.data);
        // Recreate the view over the bytes.
        return new ctor(
          bytes.buffer,
          bytes.byteOffset,
          bytes.byteLength / ctor.BYTES_PER_ELEMENT,
        );
      }
    }
  }
  return v;
}
