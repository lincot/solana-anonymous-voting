import { PublicKey } from "@solana/web3.js";
import { PROGRAM_ID } from "./constants";
import BN from "bn.js";
import { toBN } from "./utils";

export const findRelayerState = (
  targetProgram: PublicKey,
  stateId: BN | bigint,
) =>
  PublicKey.findProgramAddressSync(
    [
      Buffer.from("RELAYER_STATE"),
      targetProgram.toBuffer(),
      toBN(stateId).toArrayLike(Buffer, "le", 8),
    ],
    PROGRAM_ID,
  )[0];
