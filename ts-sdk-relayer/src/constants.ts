import { PublicKey } from "@solana/web3.js";
import zkRelayerIdl from "./idl/zk_relayer.json";

export const PROGRAM_ID = new PublicKey(zkRelayerIdl.address);

export const RELAYER_CONFIG = PublicKey.findProgramAddressSync(
  [Buffer.from("RELAYER_CONFIG")],
  PROGRAM_ID,
)[0];
