import { IdlTypes } from "@coral-xyz/anchor";
import { ZkRelayer } from "./idl/zk_relayer";

export type CompressedProof = IdlTypes<ZkRelayer>["compressedProof"];
export type Point = IdlTypes<ZkRelayer>["point"];
export type RelayerConfig = IdlTypes<ZkRelayer>["zkRelayerConfig"];
export type RelayerState = IdlTypes<ZkRelayer>["relayerState"];
