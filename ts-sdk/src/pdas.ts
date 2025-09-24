import { PublicKey } from "@solana/web3.js";
import { PROGRAM_ID } from "./constants";
import BN from "bn.js";
import { toBN } from "./utils";

export const findPoll = (
  id: bigint | BN,
) =>
  PublicKey.findProgramAddressSync(
    [Buffer.from("POLL"), toBN(id).toArrayLike(Buffer, "le", 8)],
    PROGRAM_ID,
  )[0];

export const findTally = (
  pollId: bigint | BN,
  owner: PublicKey,
) =>
  PublicKey.findProgramAddressSync(
    [
      Buffer.from("TALLY"),
      toBN(pollId).toArrayLike(Buffer, "le", 8),
      owner.toBytes(),
    ],
    PROGRAM_ID,
  )[0];
