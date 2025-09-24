import { IdlEvents } from "@coral-xyz/anchor";
import { AnonVote } from "./idl/anon_vote";
import { getProgram } from "./program";

export type VoteEvent = IdlEvents<AnonVote>["voteEvent"];

export const onVote = (
  cb: (e: VoteEvent, slot: number, signature: string) => void,
): () => void => {
  return onEvent("voteEvent", cb);
};

function onEvent<E extends keyof IdlEvents<AnonVote>>(
  eventName: E,
  cb: (e: IdlEvents<AnonVote>[E], slot: number, signature: string) => void,
): () => void {
  const prog = getProgram();
  const id = prog.addEventListener(eventName, cb);
  return () => prog.removeEventListener(id);
}
