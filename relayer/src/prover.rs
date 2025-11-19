use ark_serialize::CanonicalSerialize;
use circom_prover::{
    prover::{circom::Proof, CircomProof, ProofLib, PublicInputs},
    witness::WitnessFn,
    CircomProver,
};
use core::ops::Neg;
use serde::Serialize;
use zk_relayer::state::CompressedProof;

use crate::utils::{ser_arr_be32_as_dec, ser_be32_as_dec, ser_bool_as_u8};

fn prove<I: Serialize>(
    zkey_path: String,
    witness_fn: fn(&str) -> anyhow::Result<Vec<u8>>,
    inputs: &I,
) -> anyhow::Result<CircomProof> {
    let input_str = serde_json::to_string(inputs).unwrap();

    CircomProver::prove(
        ProofLib::Rapidsnark,
        WitnessFn::WitnessCalc(witness_fn),
        input_str,
        zkey_path,
    )
}

pub fn compress_proof(proof: Proof) -> CompressedProof {
    let mut a = [0; 32];
    let mut b = [0; 64];
    let mut c = [0; 32];

    proof
        .a
        .to_bn254()
        .neg()
        .serialize_compressed(&mut a[..])
        .unwrap();
    proof.b.to_bn254().serialize_compressed(&mut b[..]).unwrap();
    proof.c.to_bn254().serialize_compressed(&mut c[..]).unwrap();

    a.reverse();
    b.reverse();
    c.reverse();

    CompressedProof { a, b, c }
}

witnesscalc_adapter::witness!(Relay);

pub const STATE_DEPTH: usize = 64;

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct RelayInputs {
    #[serde(serialize_with = "ser_be32_as_dec")]
    pub RootQuota_before: [u8; 32],
    #[serde(serialize_with = "ser_be32_as_dec")]
    pub RootUniq_before: [u8; 32],
    #[serde(serialize_with = "ser_be32_as_dec")]
    pub MsgHash: [u8; 32],
    pub MsgLimit: u64,
    #[serde(serialize_with = "ser_be32_as_dec")]
    pub Nu: [u8; 32],
    pub PrevCount: u64,
    #[serde(serialize_with = "ser_arr_be32_as_dec")]
    pub SiblingsQuota: [[u8; 32]; STATE_DEPTH],
    #[serde(serialize_with = "ser_bool_as_u8")]
    pub NoAuxQuota: bool,
    #[serde(serialize_with = "ser_be32_as_dec")]
    pub AuxKeyQuota: [u8; 32],
    #[serde(serialize_with = "ser_be32_as_dec")]
    pub AuxValueQuota: [u8; 32],
    #[serde(serialize_with = "ser_arr_be32_as_dec")]
    pub SiblingsUniq: [[u8; 32]; STATE_DEPTH],
    #[serde(serialize_with = "ser_bool_as_u8")]
    pub NoAuxUniq: bool,
    #[serde(serialize_with = "ser_be32_as_dec")]
    pub AuxKeyUniq: [u8; 32],
    #[serde(serialize_with = "ser_be32_as_dec")]
    pub AuxValueUniq: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub struct RelayPublicInputs {
    pub root_state_before: [u8; 32],
    pub root_state_after: [u8; 32],
    pub nu_hash: [u8; 32],
    pub msg_hash: [u8; 32],
    pub msg_limit: [u8; 32],
}

impl From<&PublicInputs> for RelayPublicInputs {
    fn from(pub_inputs: &PublicInputs) -> Self {
        assert_eq!(pub_inputs.0.len(), 5);
        let mut public_inputs = [[0; 32]; 5];
        for (dst, input) in public_inputs.iter_mut().zip(&pub_inputs.0) {
            let bytes = input.to_bytes_be();
            dst[32 - bytes.len()..].copy_from_slice(&bytes);
        }

        RelayPublicInputs {
            root_state_before: public_inputs[0],
            root_state_after: public_inputs[1],
            nu_hash: public_inputs[2],
            msg_hash: public_inputs[3],
            msg_limit: public_inputs[4],
        }
    }
}

pub fn prove_relay(inputs: &RelayInputs) -> anyhow::Result<CircomProof> {
    prove(
        "build/Relay/groth16_pkey.zkey".into(),
        Relay_witness,
        inputs,
    )
}

#[cfg(test)]
mod tests {
    use circom_prover::prover::circom::{Proof, G1, G2};
    use groth16_solana::groth16::Groth16Verifier;
    use tokio::time::Instant;
    use zk_relayer::vk::VK_RELAY;

    use super::*;

    #[test]
    fn test_proof_compression() {
        let compressed_proof = compress_proof(Proof {
            a: G1 {
                x: "19596716924362148882652150385514455251882480985040799844051693182289285370925"
                    .parse()
                    .unwrap(),
                y: "15659789162636401422854192892999451382855948032688972667938976282746224441989"
                    .parse()
                    .unwrap(),
                z: 1u8.into(),
            },
            b: G2 {
                x: [
                    "16864864295050113109856231864959534395766820289809701662677144434686669477091"
                        .parse()
                        .unwrap(),
                    "2208618922981060986558413560238493369288841135951332672792969021333247685965"
                        .parse()
                        .unwrap(),
                ],
                y: [
                    "12332504024009159705241871498404886429993842423731933653702383946269369336702"
                        .parse()
                        .unwrap(),
                    "5612816923923179061363861761108646887004694837112098598334335814141984867367"
                        .parse()
                        .unwrap(),
                ],
                z: [1u8.into(), 0u8.into()],
            },
            c: G1 {
                x: "6017226879246209062531838880249486753711347442758467308737568037812363093202"
                    .parse()
                    .unwrap(),
                y: "17150350622717980887252163966787792803474488913756865349056802703745899923965"
                    .parse()
                    .unwrap(),
                z: 1u8.into(),
            },
            protocol: "groth16".into(),
            curve: "bn128".into(),
        });
        assert_eq!(
            compressed_proof,
            CompressedProof {
                a: [
                    43, 83, 89, 69, 125, 194, 37, 159, 216, 101, 137, 147, 19, 152, 32, 189, 91,
                    247, 117, 96, 242, 104, 219, 199, 36, 36, 12, 160, 228, 222, 84, 45
                ],
                b: [
                    4, 226, 8, 180, 239, 187, 212, 70, 238, 163, 94, 200, 18, 118, 137, 252, 205,
                    24, 17, 211, 176, 215, 50, 4, 100, 149, 48, 75, 97, 96, 245, 77, 37, 73, 44,
                    199, 188, 177, 164, 189, 66, 205, 105, 238, 6, 235, 186, 61, 243, 9, 218, 138,
                    121, 14, 233, 158, 85, 225, 163, 97, 178, 97, 212, 227
                ],
                c: [
                    141, 77, 161, 53, 129, 125, 59, 211, 166, 36, 70, 65, 121, 227, 113, 119, 214,
                    172, 212, 178, 143, 175, 144, 244, 36, 24, 131, 106, 91, 72, 100, 210
                ],
            }
        );
    }

    #[test]
    fn test_prover() {
        // Got inputs this way:
        //
        // for (const key of Object.keys(inputs)) {
        //   if (key === "MsgLimit" || key === "PrevCount") {
        //     console.log(`${key}: ${inputs[key]},`);
        //   } else if (key === "NoAuxQuota" || key === "NoAuxUniq") {
        //     console.log(`${key}: ${Boolean(inputs[key])},`);
        //   } else if (Array.isArray(inputs[key])) {
        //     console.log(
        //       `${key}: [${
        //         inputs[key].map((x) => "[" + toBytesBE32(x) + "]")
        //       }],`,
        //     );
        //   } else {
        //     console.log(`${key}: [${toBytesBE32(inputs[key])}],`);
        //   }
        // }

        let inputs = RelayInputs {
            RootQuota_before: [0; 32],
            RootUniq_before: [0; 32],
            MsgHash: [
                4, 80, 77, 215, 150, 85, 113, 116, 109, 1, 146, 140, 212, 148, 25, 5, 78, 209, 190,
                89, 17, 227, 80, 179, 67, 212, 230, 160, 143, 72, 164, 250,
            ],
            MsgLimit: 3,
            Nu: [
                30, 255, 43, 163, 141, 32, 191, 2, 16, 205, 0, 68, 82, 181, 155, 219, 55, 13, 165,
                208, 243, 143, 154, 168, 47, 2, 143, 105, 145, 196, 169, 89,
            ],
            PrevCount: 0,
            SiblingsQuota: [[0; 32]; 64],
            NoAuxQuota: true,
            AuxKeyQuota: [0; 32],
            AuxValueQuota: [0; 32],
            SiblingsUniq: [[0; 32]; 64],
            NoAuxUniq: true,
            AuxKeyUniq: [0; 32],
            AuxValueUniq: [0; 32],
        };
        let now = Instant::now();
        let proof = prove_relay(&inputs).unwrap();
        println!("time spent to prove {:?}", now.elapsed());

        assert!(CircomProver::verify(
            ProofLib::Rapidsnark,
            proof.clone(),
            "../build/Relay/groth16_pkey.zkey".into(),
        )
        .unwrap());

        let public_inputs = RelayPublicInputs::from(&proof.pub_inputs);
        let proof = compress_proof(proof.proof);

        assert_eq!(
            public_inputs,
            RelayPublicInputs {
                root_state_before: [
                    32, 152, 245, 251, 158, 35, 158, 171, 60, 234, 195, 242, 123, 129, 228, 129,
                    220, 49, 36, 213, 95, 254, 213, 35, 168, 57, 238, 132, 70, 182, 72, 100
                ],
                root_state_after: [
                    20, 58, 199, 41, 39, 102, 174, 55, 47, 249, 134, 126, 67, 229, 198, 76, 148,
                    217, 156, 200, 138, 102, 207, 194, 150, 0, 49, 30, 49, 155, 94, 171
                ],
                nu_hash: [
                    14, 240, 184, 171, 88, 223, 205, 137, 21, 5, 101, 14, 209, 170, 18, 75, 164,
                    33, 159, 98, 87, 235, 210, 238, 248, 179, 29, 62, 208, 21, 126, 205
                ],
                msg_hash: [
                    4, 80, 77, 215, 150, 85, 113, 116, 109, 1, 146, 140, 212, 148, 25, 5, 78, 209,
                    190, 89, 17, 227, 80, 179, 67, 212, 230, 160, 143, 72, 164, 250
                ],
                msg_limit: [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 3
                ]
            }
        );

        let proof = proof.decompress().unwrap();

        let RelayPublicInputs {
            root_state_before,
            root_state_after,
            nu_hash,
            msg_hash,
            msg_limit,
        } = public_inputs;
        let public_inputs = [
            root_state_before,
            root_state_after,
            nu_hash,
            msg_hash,
            msg_limit,
        ];

        let mut v =
            Groth16Verifier::<5>::new(&proof.a, &proof.b, &proof.c, &public_inputs, &VK_RELAY)
                .unwrap();
        v.verify().unwrap();
    }
}
