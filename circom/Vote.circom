pragma circom 2.2.2;

include "./PoseidonHasher.circom";
include "./MerkleTreeInclusionProof.circom";
include "./EdDSAPoseidonVerifier.circom";
include "babyjub.circom";
include "escalarmulfix.circom";
include "escalarmulany.circom";
include "bitify.circom";
include "comparators.circom";

template Vote(DEPTH) {
    var C_LIMBS = 6; // nullifier, choice, SecondaryKeyOld[2], SecondaryKeyNew[2]
    var C_PAD = (C_LIMBS % 3 == 0) ? C_LIMBS : C_LIMBS + (3 - (C_LIMBS % 3));
    var C_CT_LEN = C_PAD + 1;

    var R_LIMBS = 1; // nullifier
    var R_PAD = (R_LIMBS % 3 == 0) ? R_LIMBS : R_LIMBS + (3 - (R_LIMBS % 3));
    var R_CT_LEN = R_PAD + 1;

    // ---- Public ----
    signal input CensusRoot;
    signal input PollId;
    signal input N_choices;
    signal input CoordinatorPK[2];
    signal input RelayerPK[2];
    signal output MsgHash;
    signal output R_CT_hash;

    // ---- Private ----
    signal input PrimaryKey[2];
    signal input Path[DEPTH];
    signal input PathPos[DEPTH];
    signal input Choice;
    signal input SecondaryKeyNew[2];
    signal input SecondaryKeyOld[2];
    signal input SecondarySignaturePoint[2];
    signal input SecondarySignatureScalar;

    signal input PrimarySignaturePoint[2];
    signal input PrimarySignatureScalar;

    signal input ephR;
    signal input Nonce;
    signal input C_CT[C_CT_LEN];
    signal input R_CT[R_CT_LEN];

    signal root <== MerkleTreeInclusionProof(DEPTH)(
        leaf <== PoseidonHasher(2)(PrimaryKey),
        path_indices <== PathPos,
        path_elements <== Path
    );
    root === CensusRoot;

    // name = "AnonVote"; sum([ord(ch) << (8 * (len(name) - 1 - i)) for i, ch in enumerate(name)])
    var PLATFORM_NAME = 4714828379590718565;
    signal sigValid <== EdDSAPoseidonVerifier()(
        publicKeyX  <== PrimaryKey[0],
        publicKeyY  <== PrimaryKey[1],
        signatureScalar   <== PrimarySignatureScalar,
        signaturePointX <== PrimarySignaturePoint[0],
        signaturePointY <== PrimarySignaturePoint[1],
        messageHash   <== PoseidonHasher(2)([PLATFORM_NAME, PollId])
    );
    sigValid === 1;

    signal sigHash <== PoseidonHasher(3)([
        PrimarySignatureScalar,
        PrimarySignaturePoint[0],
        PrimarySignaturePoint[1]
    ]);

    signal oldPkIsZero0 <== IsZero()(SecondaryKeyOld[0]);
    signal oldPkIsZero1 <== IsZero()(SecondaryKeyOld[1]);

    signal isSecondaryNewZero0 <== IsZero()(SecondaryKeyNew[0]);
    signal isSecondaryNewZero1 <== IsZero()(SecondaryKeyNew[1]);
    isSecondaryNewZero0 * isSecondaryNewZero1 === 0;
    signal isSecondaryNewEqualToOld0 <== IsEqual()([SecondaryKeyNew[0], SecondaryKeyOld[0]]);
    signal isSecondaryNewEqualToOld1 <== IsEqual()([SecondaryKeyNew[1], SecondaryKeyOld[1]]);
    isSecondaryNewEqualToOld0 * isSecondaryNewEqualToOld1 === 0;

    signal coordinatorNu <== PoseidonHasher(1)([sigHash]);

    signal isSecondarySigValid <== EdDSAPoseidonVerifier()(
        publicKeyX <== SecondaryKeyOld[0],
        publicKeyY <== SecondaryKeyOld[1],
        signatureScalar <== SecondarySignatureScalar,
        signaturePointX <== SecondarySignaturePoint[0],
        signaturePointY <== SecondarySignaturePoint[1],
        messageHash <== PoseidonHasher(5)([
            PLATFORM_NAME,
            sigHash,
            Choice,
            SecondaryKeyNew[0],
            SecondaryKeyNew[1]
        ])
    );
    isSecondarySigValid === 1 - oldPkIsZero0 * oldPkIsZero1;

    assert(N_choices <= 65535);
    signal inRange <== LessEqThan(16)([Choice, N_choices]);
    inRange === 1;

    var BASE_X = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    var BASE_Y = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    component rBits = Num2Bits(253);
    rBits.in <== ephR;

    component Rmul = EscalarMulFix(253, [BASE_X, BASE_Y]);
    Rmul.e <== rBits.out;
    signal Rx <== Rmul.out[0];
    signal Ry <== Rmul.out[1];

    signal coordinatorSharedKey[2] <== EscalarMulAny(253)(rBits.out, CoordinatorPK);
    signal relayerSharedKey[2] <== EscalarMulAny(253)(rBits.out, RelayerPK);

    signal C_P[C_LIMBS];
    C_P[0] <== coordinatorNu;
    C_P[1] <== Choice;
    C_P[2] <== SecondaryKeyOld[0];
    C_P[3] <== SecondaryKeyOld[1];
    C_P[4] <== SecondaryKeyNew[0];
    C_P[5] <== SecondaryKeyNew[1];

    component cDec = PoseidonDecrypt(C_LIMBS);
    cDec.key <== coordinatorSharedKey;
    cDec.nonce <== Nonce;
    cDec.ciphertext <== C_CT;
    for (var i = 0; i < C_LIMBS; i++) {
        cDec.decrypted[i] === C_P[i];
    }

    signal relayerPkIsZero0 <== IsZero()(RelayerPK[0]);
    signal relayerPkIsZero1 <== IsZero()(RelayerPK[1]);
    signal relayerPkIsNonZero <== 1 - (relayerPkIsZero0 * relayerPkIsZero1);

    signal R_P[R_LIMBS];
    signal relayerNu <== PoseidonHasher(3)([sigHash, RelayerPK[0], RelayerPK[1]]);
    R_P[0] <== relayerNu * relayerPkIsNonZero;

    component rDec = PoseidonDecryptWithoutCheck(R_LIMBS);
    rDec.key <== relayerSharedKey;
    rDec.nonce <== Nonce;
    rDec.ciphertext <== R_CT;
    for (var i = 0; i < R_LIMBS; i++) {
        rDec.decrypted[i] * relayerPkIsNonZero === R_P[i];
    }
    signal r_CT_HASH <== PoseidonHasher(R_CT_LEN)(R_CT);
    R_CT_hash <== r_CT_HASH * relayerPkIsNonZero;

    component msgHasher = PoseidonHasher(3 + C_CT_LEN);
    msgHasher.inputs[0] <== Rx;
    msgHasher.inputs[1] <== Ry;
    msgHasher.inputs[2] <== Nonce;
    for (var i = 0; i < C_CT_LEN; i++) {
        msgHasher.inputs[3 + i] <== C_CT[i];
    }
    MsgHash <== msgHasher.out;
}
