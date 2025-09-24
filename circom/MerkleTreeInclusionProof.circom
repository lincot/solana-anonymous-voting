pragma circom 2.2.2;

include "./mux1.circom";

template MerkleTreeInclusionProof(n_levels) {
    signal input leaf;
    signal input path_indices[n_levels];
    signal input path_elements[n_levels];

    signal output root;

    signal level[n_levels + 1];
    level[0] <== leaf;

    for (var i = 0; i < n_levels; i++) {
        path_indices[i] * (1 - path_indices[i]) === 0;

        var mux[2][2] = [
            [level[i], path_elements[i]],
            [path_elements[i], level[i]]
        ];

        var sel[2] = MultiMux1(2)(mux, path_indices[i]);

        level[i + 1] <== PoseidonHasher(2)(sel);
    }

    root <== level[n_levels];
} 
