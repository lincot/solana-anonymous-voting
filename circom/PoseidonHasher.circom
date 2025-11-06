// This file is part of project MACI, available from its original location at
// https://github.com/privacy-ethereum/maci/blob/061530b21c50baa0b21383621035c383f0b5b240/packages/circuits/circom/utils/PoseidonHasher.circom
// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Ethereum Foundation
pragma circom 2.0.0;

// zk-kit imports
include "./poseidon-cipher.circom";

/**
 * Computes the Poseidon hash for an array of n inputs, including a default initial state 
 * of zero not counted in n. First, extends the inputs by prepending a zero, creating an array [0, inputs]. 
 * Then, the Poseidon hash of the extended inputs is calculated, with the first element of the 
 * result assigned as the output. 
 */
template PoseidonHasher(n) {
    signal input inputs[n];
    signal output out;

    // [0, inputs].
    var computedExtendedInputs[n + 1];
    computedExtendedInputs[0] = 0;

    for (var i = 0; i < n; i++) {
        computedExtendedInputs[i + 1] = inputs[i];
    }

    // Compute the Poseidon hash of the extended inputs.
    var computedPoseidonPerm[n + 1]; 
    computedPoseidonPerm = PoseidonPerm(n + 1)(computedExtendedInputs);

    out <== computedPoseidonPerm[0];
}
