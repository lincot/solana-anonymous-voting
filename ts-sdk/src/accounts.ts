import { Commitment, Connection, GetAccountInfoConfig } from "@solana/web3.js";
import { getProgram } from "./program";
import { PlatformConfig, Poll, Tally } from "./types";
import { PublicKey } from "@solana/web3.js";
import { fetchAccount } from "./utils";
import { PLATFORM_CONFIG } from "./constants";

export const fetchPoll = async (
  connection: Connection,
  publicKey: PublicKey,
  commitmentOrConfig?: Commitment | GetAccountInfoConfig,
): Promise<Poll | null> =>
  await fetchAccount(
    connection,
    getProgram().coder,
    publicKey,
    "poll",
    commitmentOrConfig,
  );

export const fetchTally = async (
  connection: Connection,
  publicKey: PublicKey,
  commitmentOrConfig?: Commitment | GetAccountInfoConfig,
): Promise<Tally | null> =>
  await fetchAccount(
    connection,
    getProgram().coder,
    publicKey,
    "tally",
    commitmentOrConfig,
  );

export const fetchPlatformConfig = async (
  connection: Connection,
  commitmentOrConfig?: Commitment | GetAccountInfoConfig,
): Promise<PlatformConfig | null> =>
  await fetchAccount(
    connection,
    getProgram().coder,
    PLATFORM_CONFIG,
    "platformConfig",
    commitmentOrConfig,
  );
