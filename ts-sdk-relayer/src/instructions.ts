import { AccountMeta, PublicKey, SystemProgram } from "@solana/web3.js";
import BN from "bn.js";
import { InstructionWithCu, toBN } from "./utils";
import { getProgram } from "./program";
import { RELAYER_CONFIG } from "./constants";
import { findRelayerState } from "./pdas";
import { CompressedProof, Point } from "./types";

export type InitializeParams = {
  payer: PublicKey;
  admin: PublicKey;
  relayerEndpoint: string;
  relayerDecryptionKey: Point;
  relayerFeeKey: PublicKey;
  fee: BN | bigint;
};

export async function initialize({
  payer,
  admin,
  relayerEndpoint,
  relayerDecryptionKey,
  relayerFeeKey,
  fee,
}: InitializeParams): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .initialize(
      {
        endpoint: relayerEndpoint,
        decryptionKey: relayerDecryptionKey,
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
  relayerDecryptionKey: Point;
  relayerFeeKey: PublicKey;
  fee: BN | bigint;
};

export async function updateConfig({
  payer,
  oldAdmin,
  newAdmin,
  relayerEndpoint,
  relayerDecryptionKey,
  relayerFeeKey,
  fee,
}: UpdateConfigParams): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .updateConfig(
      {
        endpoint: relayerEndpoint,
        decryptionKey: relayerDecryptionKey,
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
  rootAfter: number[];
  msgHash: number[];
  discriminator: number;
  ephKey: Point;
  nonce: BN | bigint;
  ciphertextHash: number[];
  data: Buffer;
  targetProgram: PublicKey;
  targetAccounts: AccountMeta[];
  targetCuLimit: number;
};

export async function relay({
  relayer,
  stateId,
  proof,
  rootAfter,
  msgHash,
  discriminator,
  ephKey,
  nonce,
  ciphertextHash,
  data,
  targetProgram,
  targetAccounts,
  targetCuLimit,
}: RelayParams): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .relay(
      toBN(stateId),
      proof,
      rootAfter,
      msgHash,
      discriminator,
      ephKey,
      toBN(nonce),
      ciphertextHash,
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
