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

export function toBytesBE(n0: bigint) {
  let n = ((n0 % FP) + FP) % FP;
  const out = Buffer.alloc(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return Array.from(out);
}
