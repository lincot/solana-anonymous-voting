pragma circom 2.2.2;

include "./PoseidonHasher.circom";
include "smt/smtverifier.circom";
include "smt/smtprocessor.circom";
include "babyjub.circom";
include "escalarmulany.circom";
include "bitify.circom";
include "poseidon-cipher.circom";
include "ecdh.circom";

template Tally(DEPTH, MAX_CHOICES, MAX_BATCH) {
    var LIMBS = 6; // nullifier, choice, RevotingKeyOld[2], RevotingKeyNew[2]
    var PAD = (LIMBS % 3 == 0) ? LIMBS : LIMBS + (3 - (LIMBS % 3));
    var CT_LEN = PAD + 1;

    // ---- Public ----
    signal input Root_before;
    signal input H_before;
    signal input TallyHash_before;
    signal output Root_after;
    signal output H_after;
    signal output TallyHash_after;

    // ---- Private ----
    signal input BatchLen;
    signal input Tally_before[MAX_CHOICES];
    signal input TallySalt_before;
    signal input TallySalt_after; // should be different for the last batch
    signal input SK; // Coordinator secret scalar

    signal input EphKey[MAX_BATCH][2];
    signal input Nonce[MAX_BATCH];
    signal input CT[MAX_BATCH][CT_LEN];

    signal input Siblings[MAX_BATCH][DEPTH];
    signal input PrevChoice[MAX_BATCH];
    signal input RevotingKeyOldActual[MAX_BATCH][2];

    signal input NoAux[MAX_BATCH];
    signal input AuxKey[MAX_BATCH];
    signal input AuxValue[MAX_BATCH];
    signal input IsPrevEmpty[MAX_BATCH];

    signal leafPrevFromMsg[MAX_BATCH];
    signal leafPrevActual[MAX_BATCH];
    signal leafNew[MAX_BATCH];
    signal leafEqual[MAX_BATCH];

    signal {binary} enabled[MAX_BATCH];

    component dec[MAX_BATCH];

    signal nu[MAX_BATCH];
    signal choice[MAX_BATCH];
    signal RevotingKeyOldFromMsg[MAX_BATCH][2];
    signal RevotingKeyNew[MAX_BATCH][2];

    signal idxBits[MAX_BATCH][DEPTH];
    signal nuLo[MAX_BATCH];
    signal nuHi[MAX_BATCH];

    signal hashNext[MAX_BATCH];

    signal hashAcc[MAX_BATCH + 1];
    signal tallyAcc[MAX_BATCH + 1][MAX_CHOICES];
    signal rootAcc[MAX_BATCH + 1];

    component msgHasher[MAX_BATCH];

    component isNew[MAX_BATCH][MAX_CHOICES];
    component isPrev[MAX_BATCH][MAX_CHOICES];

    signal indexLessThan[MAX_BATCH];

    component tallyHash_before = PoseidonHasher(1 + MAX_CHOICES);
    tallyHash_before.inputs[0] <== TallySalt_before;
    for (var i = 0; i < MAX_CHOICES; i++) {
        tallyHash_before.inputs[1 + i] <== Tally_before[i];
    }
    tallyHash_before.out === TallyHash_before;

    hashAcc[0]  <== H_before;
    tallyAcc[0] <== Tally_before;
    rootAcc[0]  <== Root_before;

    signal isFirstBatch <== IsZero()(H_before);
    for (var i = 0; i < MAX_CHOICES; i++) {
        isFirstBatch * Tally_before[i] === 0;
    }

    for (var i = 0; i < MAX_BATCH; i++) {
        msgHasher[i] = PoseidonHasher(3 + CT_LEN);
        msgHasher[i].inputs[0] <== EphKey[i][0];
        msgHasher[i].inputs[1] <== EphKey[i][1];
        msgHasher[i].inputs[2] <== Nonce[i];
        for (var k = 0; k < CT_LEN; k++) {
            msgHasher[i].inputs[3 + k] <== CT[i][k];
        }

        hashNext[i] <== PoseidonHasher(2)([hashAcc[i], msgHasher[i].out]);

        dec[i] = PoseidonDecrypt(LIMBS);
        dec[i].key <== Ecdh()(SK, EphKey[i]);
        dec[i].nonce  <== Nonce[i];
        dec[i].ciphertext <== CT[i];
        nu[i] <== dec[i].decrypted[0];
        choice[i] <== dec[i].decrypted[1];
        RevotingKeyOldFromMsg[i][0] <== dec[i].decrypted[2];
        RevotingKeyOldFromMsg[i][1] <== dec[i].decrypted[3];
        RevotingKeyNew[i][0] <== dec[i].decrypted[4];
        RevotingKeyNew[i][1] <== dec[i].decrypted[5];

        leafPrevFromMsg[i] <== PoseidonHasher(3)([
            PrevChoice[i],
            RevotingKeyOldFromMsg[i][0],
            RevotingKeyOldFromMsg[i][1]
        ]);
        leafPrevActual[i] <== PoseidonHasher(3)([
            PrevChoice[i],
            RevotingKeyOldActual[i][0],
            RevotingKeyOldActual[i][1]
        ]);
        leafNew[i] <== PoseidonHasher(3)([
            choice[i],
            RevotingKeyNew[i][0],
            RevotingKeyNew[i][1]
        ]);

        indexLessThan[i] <== LessThan(16)([i, BatchLen]);
        leafEqual[i] <== IsEqual()([leafPrevFromMsg[i], leafPrevActual[i]]);
        enabled[i] <== indexLessThan[i] * leafEqual[i];

        nuLo[i] <-- nu[i] & ((1 << DEPTH) - 1);
        nuHi[i] <-- nu[i] >> DEPTH;
        idxBits[i] <== Num2Bits(DEPTH)(nuLo[i]); // Num2Bits asserts that lo is DEPTH bits
        nu[i] === nuLo[i] + nuHi[i] * (1 << DEPTH);

        // if leaf was empty, prev choice should be 0
        IsPrevEmpty[i] * PrevChoice[i] === 0;

    	SMTVerifier(DEPTH)(
    	    enabled <== indexLessThan[i],
            root <== rootAcc[i],
            siblings <== Siblings[i],
            oldKey <== AuxKey[i], // not required for inclusion
            oldValue <== AuxValue[i], // not required for inclusion
            isOld0 <== NoAux[i], // not required for inclusion
            key <== nuLo[i],
            value <== leafPrevActual[i], // not required for non-inclusion
            fnc <== IsPrevEmpty[i]
        );

        rootAcc[i + 1] <== SMTProcessor(DEPTH)(
            oldRoot  <== rootAcc[i],
            siblings <== Siblings[i],
            oldKey   <== AuxKey[i],
            oldValue <== AuxValue[i],
            isOld0   <== NoAux[i],
            newKey   <== nuLo[i],
            newValue <== leafNew[i],
            // (1, 0) -> insert, (0, 1) -> update, (0, 0) -> no-op
            fnc      <== [enabled[i] * IsPrevEmpty[i], enabled[i] * (1 - IsPrevEmpty[i])]
        );

        for (var t = 0; t < MAX_CHOICES; t++) {
          isNew[i][t] = IsEqual();
          isNew[i][t].in[0] <== choice[i];
          isNew[i][t].in[1] <== t + 1;

          isPrev[i][t] = IsEqual();
          isPrev[i][t].in[0] <== PrevChoice[i];
          isPrev[i][t].in[1] <== t + 1;

          tallyAcc[i + 1][t] <== tallyAcc[i][t] + enabled[i] * (isNew[i][t].out - isPrev[i][t].out);
        }

        hashAcc[i + 1] <== hashAcc[i] + indexLessThan[i] * (hashNext[i] - hashAcc[i]);
    }

    component tallyHash_after = PoseidonHasher(1 + MAX_CHOICES);
    tallyHash_after.inputs[0] <== TallySalt_after;
    for (var i = 0; i < MAX_CHOICES; i++) {
        tallyHash_after.inputs[1 + i] <== tallyAcc[MAX_BATCH][i];
    }

    H_after     <== hashAcc[MAX_BATCH];
    TallyHash_after <== tallyHash_after.out;
    Root_after  <== rootAcc[MAX_BATCH];
}
