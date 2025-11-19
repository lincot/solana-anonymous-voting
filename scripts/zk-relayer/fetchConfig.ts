import * as anchor from "@coral-xyz/anchor";
import { fetchRelayerConfig } from "@lincot/zk-relayer-sdk";

async function main(): Promise<void> {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const config = await fetchRelayerConfig(provider.connection);
  if (!config) {
    console.error("config not initialized");
    return;
  }

  console.log("Admin:", config.admin.toString());
  console.log("Fee:", config.fee.toString());
  console.log("Relayer endpoint:", config.relayer.endpoint.toString());
  console.log("Relayer fee key:", config.relayer.feeKey.toString());
}

main();
