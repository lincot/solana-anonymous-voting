import { AnchorProvider, Program } from "@coral-xyz/anchor";
import { ZkRelayer } from "./idl/zk_relayer";
import zkRelayerIdl from "./idl/zk_relayer.json";
import { createStubObject } from "./utils";

let _program: Program<ZkRelayer> | undefined;

const getStubProvider = () =>
  createStubObject(
    "Provider has not been set. Call `setProvider(provider)` before using this function.",
  ) as AnchorProvider;

export const getProgram =
  () => (_program ??= new Program(zkRelayerIdl, getStubProvider()));

/** Call once, early, to supply the RPC provider. */
export const setProvider = (provider: AnchorProvider) => {
  _program = new Program(zkRelayerIdl, provider);
};
