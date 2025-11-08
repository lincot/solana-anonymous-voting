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
    var LIMBS = 6; // nullifier, choice, RevotingKeyOld[2], RevotingKeyNew[2]
    var PAD = (LIMBS % 3 == 0) ? LIMBS : LIMBS + (3 - (LIMBS % 3));
    var CT_LEN = PAD + 1;

    // ---- Public ----
    signal input CensusRoot;
    signal input PollId;
    signal input N_choices;
    signal input CoordinatorPK[2];
    signal input RelayerId;
    signal output MsgHash;
    signal output RelayerNuHash;

    // ---- Private ----
    signal input Key[2];
    signal input Path[DEPTH];
    signal input PathPos[DEPTH];
    signal input Choice;
    signal input RevotingKeyNew[2];
    signal input RevotingKeyOld[2];
    signal input RevotingSignaturePoint[2];
    signal input RevotingSignatureScalar;

    signal input SignaturePoint[2];
    signal input SignatureScalar;

    signal input ephR;
    signal input Nonce;
    signal input CT[CT_LEN];

    signal root <== MerkleTreeInclusionProof(DEPTH)(
        leaf <== PoseidonHasher(2)(Key),
        path_indices <== PathPos,
        path_elements <== Path
    );
    root === CensusRoot;

    // name = "AnonVote"; sum([ord(ch) << (8 * (len(name) - 1 - i)) for i, ch in enumerate(name)])
    var PLATFORM_NAME = 4714828379590718565;
    signal sigValid <== EdDSAPoseidonVerifier()(
        publicKeyX  <== Key[0],
        publicKeyY  <== Key[1],
        signatureScalar   <== SignatureScalar,
        signaturePointX <== SignaturePoint[0],
        signaturePointY <== SignaturePoint[1],
        messageHash   <== PoseidonHasher(2)([PLATFORM_NAME, PollId])
    );
    sigValid === 1;

    signal sigHash <== PoseidonHasher(3)([
        SignatureScalar,
        SignaturePoint[0],
        SignaturePoint[1]
    ]);

    signal oldPkIsZero0 <== IsZero()(RevotingKeyOld[0]);
    signal oldPkIsZero1 <== IsZero()(RevotingKeyOld[1]);

    signal isRevotingNewZero0 <== IsZero()(RevotingKeyNew[0]);
    signal isRevotingNewZero1 <== IsZero()(RevotingKeyNew[1]);
    isRevotingNewZero0 * isRevotingNewZero1 === 0;
    signal isRevotingNewEqualToOld0 <== IsEqual()([RevotingKeyNew[0], RevotingKeyOld[0]]);
    signal isRevotingNewEqualToOld1 <== IsEqual()([RevotingKeyNew[1], RevotingKeyOld[1]]);
    isRevotingNewEqualToOld0 * isRevotingNewEqualToOld1 === 0;

    signal coordinatorNu <== PoseidonHasher(1)([sigHash]);

    signal isRevotingSigValid <== EdDSAPoseidonVerifier()(
        publicKeyX <== RevotingKeyOld[0],
        publicKeyY <== RevotingKeyOld[1],
        signatureScalar <== RevotingSignatureScalar,
        signaturePointX <== RevotingSignaturePoint[0],
        signaturePointY <== RevotingSignaturePoint[1],
        messageHash <== PoseidonHasher(5)([
            PLATFORM_NAME,
            sigHash,
            Choice,
            RevotingKeyNew[0],
            RevotingKeyNew[1]
        ])
    );
    isRevotingSigValid === 1 - oldPkIsZero0 * oldPkIsZero1;

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

    signal P[LIMBS];
    P[0] <== coordinatorNu;
    P[1] <== Choice;
    P[2] <== RevotingKeyOld[0];
    P[3] <== RevotingKeyOld[1];
    P[4] <== RevotingKeyNew[0];
    P[5] <== RevotingKeyNew[1];

    component cDec = PoseidonDecrypt(LIMBS);
    cDec.key <== coordinatorSharedKey;
    cDec.nonce <== Nonce;
    cDec.ciphertext <== CT;
    for (var i = 0; i < LIMBS; i++) {
        cDec.decrypted[i] === P[i];
    }

    component msgHasher = PoseidonHasher(3 + CT_LEN);
    msgHasher.inputs[0] <== Rx;
    msgHasher.inputs[1] <== Ry;
    msgHasher.inputs[2] <== Nonce;
    for (var i = 0; i < CT_LEN; i++) {
        msgHasher.inputs[3 + i] <== CT[i];
    }
    MsgHash <== msgHasher.out;

    signal relayerNu <== PoseidonHasher(2)([sigHash, RelayerId]);
    signal relayerNuHash <== PoseidonHasher(2)([relayerNu, MsgHash]);
    signal relayerIsNotProvided <== IsZero()(RelayerId);
    RelayerNuHash <== relayerNuHash * (1 - relayerIsNotProvided);
}
