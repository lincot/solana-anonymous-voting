import { PublicKey } from "@solana/web3.js";
import anonVoteIdl from "./idl/anon_vote.json";

export const PROGRAM_ID = new PublicKey(anonVoteIdl.address);

export const PLATFORM_NAME = 4714828379590718565n;

export const PLATFORM_CONFIG = PublicKey.findProgramAddressSync(
  [Buffer.from("PLATFORM_CONFIG")],
  PROGRAM_ID,
)[0];
