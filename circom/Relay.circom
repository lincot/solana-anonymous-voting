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
    signal input Root_before;
    signal input MsgHash;
    signal input MsgLimit;
    signal output Root_after;
    signal output CT_hash;

    // ---- Private ----
    signal input SK; // Relayer secret scalar

    signal input EphKey[2];
    signal input Nonce;
    signal input CT[CT_LEN];

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

    component dec = PoseidonDecrypt(LIMBS);
    dec.key <== Ecdh()(SK, EphKey);
    dec.nonce <== Nonce;
    dec.ciphertext <== CT;
    signal nu <== dec.decrypted[0];

    signal nuLo <-- nu & ((1 << DEPTH) - 1);
    signal nuHi <-- nu >> DEPTH;
    signal idxBits[DEPTH] <== Num2Bits(DEPTH)(nuLo); // Num2Bits asserts that lo is DEPTH bits
    nu === nuLo + nuHi * (1 << DEPTH);

    signal isPrevEmpty <== IsZero()(PrevCount);

    SMTVerifier(DEPTH)(
	    enabled <== 1,
        root <== Root_before,
        siblings <== SiblingsQuota,
        oldKey <== AuxKeyQuota, // not required for inclusion
        oldValue <== AuxValueQuota, // not required for inclusion
        isOld0 <== NoAuxQuota, // not required for inclusion
        key <== nuLo,
        value <== PrevCount, // not required for non-inclusion
        fnc <== isPrevEmpty
    );

    signal rootAfterQuota <== SMTProcessor(DEPTH)(
        oldRoot  <== Root_before,
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
        root <== rootAfterQuota,
        siblings <== SiblingsUniq,
        oldKey <== AuxKeyUniq,
        oldValue <== AuxValueUniq,
        isOld0 <== NoAuxUniq,
        key <== MsgHash,
        value <== 0,
        fnc <== 1
    );

    Root_after <== SMTProcessor(DEPTH)(
        oldRoot  <== rootAfterQuota,
        siblings <== SiblingsUniq,
        oldKey   <== AuxKeyUniq,
        oldValue <== AuxValueUniq,
        isOld0   <== NoAuxUniq,
        newKey   <== MsgHash,
        newValue <== 1,
        // (1, 0) -> insert
        fnc      <== [1, 0]
    );    

    CT_hash <== PoseidonHasher(CT_LEN)(CT);
}
