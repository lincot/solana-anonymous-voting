import { AnchorProvider, Program } from "@coral-xyz/anchor";
import { AnonVote } from "./idl/anon_vote";
import anonvoteIdl from "./idl/anon_vote.json";
import { createStubObject } from "./utils";

let _program: Program<AnonVote> | undefined;

const getStubProvider = () =>
  createStubObject(
    "Provider has not been set. Call `setProvider(provider)` before using this function.",
  ) as AnchorProvider;

export const getProgram =
  () => (_program ??= new Program(anonvoteIdl, getStubProvider()));

/** Call once, early, to supply the RPC provider. */
export const setProvider = (provider: AnchorProvider) => {
  _program = new Program(anonvoteIdl, provider);
};
