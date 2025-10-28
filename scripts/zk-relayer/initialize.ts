import * as anchor from "@coral-xyz/anchor";
import NodeWallet from "@coral-xyz/anchor/dist/cjs/nodewallet.js";
import { initialize, toTransaction } from "@lincot/zk-relayer-sdk";
import { expect } from "chai";
import { sendAndConfirmVersionedTx } from "../../helpers/utils.ts";

async function main(): Promise<void> {
  if (process.argv.length < 2 + 4) {
    console.error(
      "Usage: initialize <fee> <decryptionKeyX> <decryptionKeyY> <endpoint>",
    );
    process.exit(1);
  }

  const fee = BigInt(process.argv[2]);
  const x = hexToBytes32(process.argv[3]);
  const y = hexToBytes32(process.argv[4]);
  const relayerEndpoint = process.argv[5];

  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const payer = (provider.wallet as NodeWallet).payer;

  try {
    const ix = await initialize({
      admin: payer.publicKey,
      fee: fee,
      payer: payer.publicKey,
      relayerDecryptionKey: { x, y },
      relayerEndpoint,
      relayerFeeKey: payer.publicKey,
    });
    const transactionSignature = await sendAndConfirmVersionedTx(
      provider.connection,
      toTransaction(
        [ix],
        await provider.connection.getLatestBlockhash().then((b) => b.blockhash),
        payer,
      ),
      [payer],
      payer.publicKey,
    );

    console.log("Transaction signature:", transactionSignature);
  } catch (e) {
    expect(e.toString()).to.include("already in use");
  }
}

const hexToBytes32 = (hex: string): number[] => {
  const s = hex.replace(/^0x/, "");
  if (s.length !== 64) throw new Error("Expected 32-byte hex");
  const out = Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
};

main();
