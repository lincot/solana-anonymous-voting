import { Commitment, Connection, GetAccountInfoConfig } from "@solana/web3.js";
import { getProgram } from "./program";
import { RelayerConfig, RelayerState } from "./types";
import { PublicKey } from "@solana/web3.js";
import { fetchAccount } from "./utils";
import { RELAYER_CONFIG } from "./constants";

export const fetchRelayerConfig = async (
  connection: Connection,
  commitmentOrConfig?: Commitment | GetAccountInfoConfig,
): Promise<RelayerConfig | null> =>
  await fetchAccount(
    connection,
    getProgram().coder,
    RELAYER_CONFIG,
    "zkRelayerConfig",
    commitmentOrConfig,
  );

export const fetchRelayerState = async (
  connection: Connection,
  publicKey: PublicKey,
  commitmentOrConfig?: Commitment | GetAccountInfoConfig,
): Promise<RelayerState | null> =>
  await fetchAccount(
    connection,
    getProgram().coder,
    publicKey,
    "relayerState",
    commitmentOrConfig,
  );
