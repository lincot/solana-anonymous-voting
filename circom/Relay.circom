pragma circom 2.2.2;

include "./PoseidonHasher.circom";
include "smt/smtverifier.circom";
include "smt/smtprocessor.circom";
include "babyjub.circom";
include "escalarmulany.circom";
include "bitify.circom";
include "poseidon-cipher.circom";
include "ecdh.circom";

template Relay(DEPTH) {
    var LIMBS = 1; // nullifier
    var PAD = (LIMBS % 3 == 0) ? LIMBS : LIMBS + (3 - (LIMBS % 3));
    var CT_LEN = PAD + 1;

    // ---- Public ----
    signal input MsgHash;
    signal input MsgLimit;
    signal output Root_state_before;
    signal output Root_state_after;
    signal output NuHash;

    // ---- Private ----
    signal input Nu;

    signal input RootQuota_before;
    signal input RootUniq_before;

    signal input PrevCount;
    signal input SiblingsQuota[DEPTH];
    signal input NoAuxQuota;
    signal input AuxKeyQuota;
    signal input AuxValueQuota;

    signal input SiblingsUniq[DEPTH];
    signal input NoAuxUniq;
    signal input AuxKeyUniq;
    signal input AuxValueUniq;

    signal lessThan <== LessThan(16)([PrevCount, MsgLimit]);
    lessThan === 1;

    signal nuLo <-- Nu & ((1 << DEPTH) - 1);
    signal nuHi <-- Nu >> DEPTH;
    signal idxBits[DEPTH] <== Num2Bits(DEPTH)(nuLo); // Num2Bits asserts that lo is DEPTH bits
    Nu === nuLo + nuHi * (1 << DEPTH);

    signal isPrevEmpty <== IsZero()(PrevCount);

    SMTVerifier(DEPTH)(
        enabled <== 1,
        root <== RootQuota_before,
        siblings <== SiblingsQuota,
        oldKey <== AuxKeyQuota, // not required for inclusion
        oldValue <== AuxValueQuota, // not required for inclusion
        isOld0 <== NoAuxQuota, // not required for inclusion
        key <== nuLo,
        value <== PrevCount, // not required for non-inclusion
        fnc <== isPrevEmpty
    );

    signal rootQuota_after <== SMTProcessor(DEPTH)(
        oldRoot  <== RootQuota_before,
        siblings <== SiblingsQuota,
        oldKey   <== AuxKeyQuota,
        oldValue <== AuxValueQuota,
        isOld0   <== NoAuxQuota,
        newKey   <== nuLo,
        newValue <== PrevCount + 1,
        // (1, 0) -> insert, (0, 1) -> update, (0, 0) -> no-op
        fnc      <== [isPrevEmpty, 1 - isPrevEmpty]
    );

    SMTVerifier(DEPTH)(
        enabled <== 1,
        root <== RootUniq_before,
        siblings <== SiblingsUniq,
        oldKey <== AuxKeyUniq,
        oldValue <== AuxValueUniq,
        isOld0 <== NoAuxUniq,
        key <== MsgHash,
        value <== 0,
        fnc <== 1
    );

    signal rootUniq_after <== SMTProcessor(DEPTH)(
        oldRoot  <== RootUniq_before,
        siblings <== SiblingsUniq,
        oldKey   <== AuxKeyUniq,
        oldValue <== AuxValueUniq,
        isOld0   <== NoAuxUniq,
        newKey   <== MsgHash,
        newValue <== 1,
        // (1, 0) -> insert
        fnc      <== [1, 0]
    );

    NuHash <== PoseidonHasher(2)([Nu, MsgHash]);
    Root_state_before <== PoseidonHasher(2)([RootQuota_before, RootUniq_before]);
    Root_state_after <== PoseidonHasher(2)([rootQuota_after, rootUniq_after]);
}
