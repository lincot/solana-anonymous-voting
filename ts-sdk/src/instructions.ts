import { PublicKey } from "@solana/web3.js";
import BN from "bn.js";
import { InstructionWithCu, toBN } from "./utils";
import { getProgram } from "./program";
import { PLATFORM_CONFIG, PROGRAM_ID } from "./constants";
import { findPoll, findTally } from "./pdas";
import { CompressedProof, Point } from "./types";
import {
  findRelayerState,
  relay,
  RELAYER_CONFIG,
} from "@lincot/zk-relayer-sdk";

export type InitializeParams = {
  payer: PublicKey;
  admin: PublicKey;
  fee: BN | bigint;
  feeDestination: PublicKey;
};

export async function initialize({
  payer,
  admin,
  fee,
  feeDestination,
}: InitializeParams): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .initialize(
      admin,
      toBN(fee),
      feeDestination,
    )
    .accounts({ payer, platformConfig: PLATFORM_CONFIG })
    .instruction();

  return {
    instruction,
    cuLimit: 200_000,
  };
}

export type UpdateConfigParams = {
  oldAdmin: PublicKey;
  newAdmin: PublicKey;
  fee: BN | bigint;
  feeDestination: PublicKey;
};

export async function updateConfig({
  oldAdmin,
  newAdmin,
  fee,
  feeDestination,
}: UpdateConfigParams): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .updateConfig(
      newAdmin,
      toBN(fee),
      feeDestination,
    )
    .accountsStrict({ admin: oldAdmin, platformConfig: PLATFORM_CONFIG })
    .instruction();

  return {
    instruction,
    cuLimit: 200_000,
  };
}

export type CreatePollParams = {
  payer: PublicKey;
  id: BN | bigint;
  nChoices: number;
  descriptionUrl: string;
  censusUrl: string;
  coordinatorKey: Point;
  censusRoot: number[];
  votingStartTime: BN | bigint;
  votingEndTime: BN | bigint;
  fee: BN | bigint;
  feeDestination: PublicKey;
  nVoters: BN | bigint;
};

export async function createPoll({
  payer,
  id,
  nChoices,
  descriptionUrl,
  censusUrl,
  coordinatorKey,
  censusRoot,
  votingStartTime,
  votingEndTime,
  fee,
  feeDestination,
  nVoters,
}: CreatePollParams): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .createPoll(
      toBN(id),
      nChoices,
      descriptionUrl,
      censusUrl,
      coordinatorKey,
      censusRoot,
      toBN(votingStartTime),
      toBN(votingEndTime),
      toBN(fee),
      feeDestination,
      toBN(nVoters),
    )
    .accounts({
      payer,
      poll: findPoll(id),
      platformConfig: PLATFORM_CONFIG,
      relayerConfig: RELAYER_CONFIG,
      relayerState: findRelayerState(PROGRAM_ID, id),
    })
    .instruction();

  return {
    instruction,
    cuLimit: 200_000,
  };
}

export type VoteParams = {
  payer: PublicKey;
  ephKey: Point;
  nonce: BN | bigint;
  ciphertext: number[][];
  pollId: BN | bigint;
  proof: CompressedProof;
  platformFeeDestination: PublicKey;
  pollFeeDestination: PublicKey;
};

export async function vote({
  payer,
  ephKey,
  nonce,
  ciphertext,
  pollId,
  proof,
  platformFeeDestination,
  pollFeeDestination,
}: VoteParams): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .vote(
      ephKey,
      toBN(nonce),
      ciphertext,
      proof,
    )
    .accounts({
      payer,
      pollFeeDestination,
      voteCommon: {
        poll: findPoll(pollId),
        platformFeeDestination,
        platformConfig: PLATFORM_CONFIG,
      },
    })
    .instruction();

  return {
    instruction,
    cuLimit: 200_000,
  };
}

export type VoteWithRelayerParams = {
  relayer: PublicKey;
  msgHash: number[];
  ephKey: Point;
  nonce: BN | bigint;
  ciphertext: number[][];
  relayerNuHash: number[];
  pollId: BN | bigint;
  proof: CompressedProof;
  relayerProof: CompressedProof;
  rootAfter: number[];
  platformFeeDestination: PublicKey;
};

export async function voteWithRelayer({
  relayer,
  msgHash,
  ephKey,
  nonce,
  ciphertext,
  relayerNuHash,
  pollId,
  proof,
  relayerProof,
  rootAfter,
  platformFeeDestination,
}: VoteWithRelayerParams): Promise<InstructionWithCu> {
  const data = serializeVoteData({
    ciphertext,
    proof,
    ephKey,
    nonce,
  });
  return relay({
    stateId: pollId,
    relayer,
    data,
    discriminator: 4,
    msgHash,
    nuHash: relayerNuHash,
    proof: relayerProof,
    rootAfter,
    targetAccounts: [{
      isSigner: false,
      isWritable: false,
      pubkey: PLATFORM_CONFIG,
    }, {
      isSigner: false,
      isWritable: true,
      pubkey: findPoll(pollId),
    }, {
      isSigner: false,
      isWritable: true,
      pubkey: platformFeeDestination,
    }],
    targetCuLimit: 200_000,
    targetProgram: PROGRAM_ID,
  });
}

export type CreateTallyParams = {
  pollId: BN | bigint;
  payer: PublicKey;
  initialTallyHash: number[];
};

export async function createTally(
  { pollId, payer, initialTallyHash }: CreateTallyParams,
): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .createTally(
      toBN(pollId),
      initialTallyHash,
    )
    .accounts({ tally: findTally(pollId, payer), payer })
    .instruction();

  return {
    instruction,
    cuLimit: 200_000,
  };
}

export type TallyBatchParams = {
  pollId: BN | bigint;
  owner: PublicKey;
  proof: CompressedProof;
  rootAfter: number[];
  runningMsgHashAfter: number[];
  tallyHashAfter: number[];
};

export async function tallyBatch(
  { pollId, owner, proof, rootAfter, runningMsgHashAfter, tallyHashAfter }:
    TallyBatchParams,
): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .tallyBatch(
      proof,
      rootAfter,
      runningMsgHashAfter,
      tallyHashAfter,
    )
    .accounts({ tally: findTally(pollId, owner) })
    .instruction();

  return {
    instruction,
    cuLimit: 200_000,
  };
}

export type FinishTallyParams = {
  pollId: BN | bigint;
  payer: PublicKey;
  tally: (BN | bigint)[];
  tallySalt: BN | bigint;
};

export async function finishTally(
  { pollId, payer, tally, tallySalt }: FinishTallyParams,
): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .finishTally(
      tally.map(toBN),
      toBN(tallySalt),
    )
    .accounts({
      payer,
      tally: findTally(pollId, payer),
      poll: findPoll(pollId),
    })
    .instruction();

  return {
    instruction,
    cuLimit: 200_000,
  };
}

export type CloseTallyParams = {
  pollId: BN | bigint;
  owner: PublicKey;
};

export async function closeTally(
  { pollId, owner }: CloseTallyParams,
): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .closeTally(
      toBN(pollId),
    )
    .accounts({
      owner,
      tally: findTally(pollId, owner),
    })
    .instruction();

  return {
    instruction,
    cuLimit: 200_000,
  };
}

export type WithdrawPollParams = {
  id: BN | bigint;
  feeDestination: PublicKey;
};

export async function withdrawPoll(
  { id, feeDestination }: WithdrawPollParams,
): Promise<InstructionWithCu> {
  const instruction = await getProgram().methods
    .withdrawPoll()
    .accountsStrict({
      feeDestination,
      poll: findPoll(id),
    })
    .instruction();

  return {
    instruction,
    cuLimit: 200_000,
  };
}

type SerializeVoteDataParams = {
  ciphertext: number[][];
  proof: CompressedProof;
  ephKey: Point;
  nonce: BN | bigint;
};

function serializeVoteData({
  ciphertext,
  proof,
  ephKey,
  nonce,
}: SerializeVoteDataParams): Buffer {
  const res = Buffer.alloc(
    ephKey.x.length + ephKey.y.length + 8 +
      ciphertext.length * ciphertext[0].length + proof.a.length +
      proof.b.length +
      proof.c.length,
  );
  let offset = 0;
  res.set(ephKey.x, offset);
  offset += ephKey.x.length;
  res.set(ephKey.y, offset);
  offset += ephKey.y.length;
  res.set(toBN(nonce).toArrayLike(Buffer, "le", 8), offset);
  offset += 8;
  for (const c of ciphertext) {
    res.set(c, offset);
    offset += c.length;
  }
  res.set(proof.a, offset);
  offset += proof.a.length;
  res.set(proof.b, offset);
  offset += proof.b.length;
  res.set(proof.c, offset);
  offset += proof.c.length;
  return res;
}
