import { IdlTypes } from "@coral-xyz/anchor";
import { AnonVote } from "./idl/anon_vote";

export type CompressedProof = IdlTypes<AnonVote>["compressedProof"];
export type Point = IdlTypes<AnonVote>["point"];
export type Poll = IdlTypes<AnonVote>["poll"];
export type Tally = IdlTypes<AnonVote>["tally"];
export type PlatformConfig = IdlTypes<AnonVote>["platformConfig"];
