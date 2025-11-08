import { IdlTypes } from "@coral-xyz/anchor";
import { ZkRelayer } from "./idl/zk_relayer";

export type CompressedProof = IdlTypes<ZkRelayer>["compressedProof"];
export type RelayerConfig = IdlTypes<ZkRelayer>["zkRelayerConfig"];
export type RelayerState = IdlTypes<ZkRelayer>["relayerState"];
