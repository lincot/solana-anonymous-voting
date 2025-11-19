import { AccountMeta, PublicKey, SystemProgram } from "@solana/web3.js";
import BN from "bn.js";
import { InstructionWithCu, toBN } from "./utils";
import { getProgram } from "./program";
import { RELAYER_CONFIG } from "./constants";
import { findRelayerState } from "./pdas";
import { CompressedProof } from "./types";

export type InitializeParams = {
  payer: PublicKey;
  admin: PublicKey;
  relayerEndpoint: string;
  relayerFeeKey: PublicKey;
  fee: BN | bigint;
};

export async function initialize({
  payer,
  admin,
  relayerEndpoint,
  relayerFeeKey,
  fee,
}: InitializeParams): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .initialize(
      {
        endpoint: relayerEndpoint,
        feeKey: relayerFeeKey,
      },
      admin,
      toBN(fee),
    )
    .accounts({ payer, relayerConfig: RELAYER_CONFIG })
    .instruction();

  return {
    instruction,
    cuLimit: 200_000,
  };
}

export type UpdateConfigParams = {
  payer: PublicKey;
  oldAdmin: PublicKey;
  newAdmin: PublicKey;
  relayerEndpoint: string;
  relayerFeeKey: PublicKey;
  fee: BN | bigint;
};

export async function updateConfig({
  payer,
  oldAdmin,
  newAdmin,
  relayerEndpoint,
  relayerFeeKey,
  fee,
}: UpdateConfigParams): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .updateConfig(
      {
        endpoint: relayerEndpoint,
        feeKey: relayerFeeKey,
      },
      newAdmin,
      toBN(fee),
    )
    .accountsStrict({
      payer,
      relayerConfig: RELAYER_CONFIG,
      admin: oldAdmin,
      systemProgram: SystemProgram.programId,
    })
    .instruction();

  return {
    instruction,
    cuLimit: 200_000,
  };
}

export type RelayParams = {
  relayer: PublicKey;
  stateId: BN | bigint;
  proof: CompressedProof;
  rootStateAfter: number[];
  msgHash: number[];
  discriminator: number;
  nuHash: number[];
  data: Buffer;
  targetProgram: PublicKey;
  targetAccounts: AccountMeta[];
  targetCuLimit: number;
};

export async function relay({
  relayer,
  stateId,
  proof,
  rootStateAfter,
  msgHash,
  discriminator,
  nuHash,
  data,
  targetProgram,
  targetAccounts,
  targetCuLimit,
}: RelayParams): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .relay(
      toBN(stateId),
      proof,
      rootStateAfter,
      msgHash,
      discriminator,
      nuHash,
      data,
    )
    .accounts({
      relayer,
      relayerConfig: RELAYER_CONFIG,
      relayerState: findRelayerState(targetProgram, stateId),
      targetProgram,
    })
    .remainingAccounts(targetAccounts)
    .instruction();

  return {
    instruction,
    cuLimit: 200_000 + targetCuLimit,
  };
}
