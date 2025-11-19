import * as anchor from "@coral-xyz/anchor";
import NodeWallet from "@coral-xyz/anchor/dist/cjs/nodewallet.js";
import { toTransaction, updateConfig } from "@lincot/zk-relayer-sdk";
import { expect } from "chai";
import { sendAndConfirmVersionedTx } from "../../helpers/utils.ts";
import { PublicKey } from "@solana/web3.js";

async function main(): Promise<void> {
  if (process.argv.length < 2 + 3) {
    console.error("Usage: updateConfig <fee> <endpoint> <newAdmin>");
    process.exit(1);
  }

  const fee = BigInt(process.argv[2]);
  const relayerEndpoint = process.argv[3];
  const newAdmin = new PublicKey(process.argv[4]);

  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const payer = (provider.wallet as NodeWallet).payer;

  const ix = await updateConfig({
    oldAdmin: payer.publicKey,
    newAdmin,
    fee: fee,
    payer: payer.publicKey,
    relayerEndpoint,
    relayerFeeKey: newAdmin,
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
}

main();
