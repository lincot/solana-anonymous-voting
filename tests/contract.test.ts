import {
  closeTally,
  createPoll,
  createTally,
  fetchPlatformConfig,
  fetchPoll,
  fetchTally,
  findPoll,
  findTally,
  finishTally,
  initialize,
  type InstructionWithCu,
  onVote,
  PLATFORM_NAME,
  PROGRAM_ID,
  setProvider,
  tallyBatch,
  toTransaction,
  updateConfig,
  vote,
  voteWithRelayer,
  withdrawPoll,
} from "@lincot/anon-vote-sdk";
import {
  fetchRelayerConfig,
  fetchRelayerState,
  findRelayerState,
  initialize as initializeRelayer,
  updateConfig as updateRelayerConfig,
} from "@lincot/zk-relayer-sdk";
import {
  Keypair,
  type Signer,
  type TransactionSignature,
} from "@solana/web3.js";
import { before, describe, test } from "mocha";
import * as chai from "chai";
import chaiAsPromised from "chai-as-promised";
import { expect } from "chai";
import {
  disperse,
  sendAndConfirmVersionedTx,
  setupTests,
  toBigint,
  toBytesBE,
} from "../helpers/utils.ts";
import {
  type BabyJub,
  buildBabyjub,
  buildEddsa,
  buildPoseidon,
  type Eddsa,
  type Poseidon,
} from "circomlibjs";
import { poseidonDecrypt, poseidonEncrypt } from "@zk-kit/poseidon-cipher";
import { groth16 } from "snarkjs";
import { readFileSync } from "fs";
import { genBabyJubKeypair, randomScalar } from "./helpers.ts";
import { compressProofForSolana, serProof } from "../helpers/exportSolana.ts";
import { getMerkleProof, getMerkleRoot } from "../helpers/merkletree.ts";
import {
  CircomProcessorProof,
  CircomVerifierProof,
  ErrEntryIndexAlreadyExists,
  InMemoryDB,
  Merkletree,
  ZERO_HASH,
} from "@iden3/js-merkletree";
import { mulPointEscalar } from "@zk-kit/baby-jubjub";
import anchor from "@coral-xyz/anchor";

const { BN } = anchor;

chai.use(chaiAsPromised);

const { provider, payer } = setupTests();
const connection = provider.connection;

setProvider(provider);

const sendTx = async (
  ixs: InstructionWithCu[],
  signers: Signer[] = [payer],
): Promise<TransactionSignature> => {
  const tx = toTransaction(
    ixs,
    await connection.getLatestBlockhash().then((x) => x.blockhash),
    payer,
  );
  return await sendAndConfirmVersionedTx(
    connection,
    tx,
    signers,
    signers[0].publicKey,
  );
};

const sendIx = async (
  ix: InstructionWithCu,
  signers: Signer[] = [payer],
): Promise<TransactionSignature> => sendTx([ix], signers);

let poseidon: Poseidon;
let eddsa: Eddsa;
let babyjub: BabyJub;
let F: any;

type Voter = {
  prvPrimary: Uint8Array;
  pubPrimary: [Uint8Array, Uint8Array];
};

const voters: Voter[] = [];
const census: bigint[] = [];
let CensusRoot: bigint;

type Message = {
  ephKey: [bigint, bigint];
  nonce: bigint;
  ciphertext: bigint[];
};

const messages: Message[] = [];

const CENSUS_DEPTH = 40;
const STATE_DEPTH = 64;
const N_VOTERS = 3;

const MSG_LIMIT = 3n;

const pollFeeDestination = new Keypair();
const platformFeeDestination = new Keypair();

const admin = new Keypair();

const platformFee = 100_000n;
const pollFee = 200_000n;

before(async () => {
  await disperse(
    connection,
    [
      platformFeeDestination.publicKey,
      pollFeeDestination.publicKey,
      relayer.publicKey,
    ],
    payer,
    200_000_000,
  );

  poseidon = await buildPoseidon();
  eddsa = await buildEddsa();
  babyjub = await buildBabyjub();
  F = poseidon.F;

  for (let i = 0; i < N_VOTERS; i++) {
    const prvPrimary = F.e(i);
    const pubPrimary = eddsa.prv2pub(prvPrimary);
    voters.push({ prvPrimary, pubPrimary });
    census.push(
      F.toObject(
        poseidon([F.toObject(pubPrimary[0]), F.toObject(pubPrimary[1])]),
      ),
    );
  }

  CensusRoot = await getMerkleRoot(CENSUS_DEPTH, census);
});

let R_SK: bigint;
let relayerPK: [bigint, bigint];
const relayer = new Keypair();
const relayerFee = 100_000n;

describe("ZK Relayer", () => {
  const tempAdmin = new Keypair();

  test("initialize", async () => {
    const { sk: sk_, PKx: R_PKx0, PKy: R_PKy0 } = await genBabyJubKeypair(
      babyjub,
    );
    R_SK = sk_;
    relayerPK = [F.toObject(R_PKx0), F.toObject(R_PKy0)];

    const relayerDecryptionKey = {
      x: toBytesBE(relayerPK[0]),
      y: toBytesBE(relayerPK[1]),
    };
    const relayerEndpoint = "https://test.test";
    const fee = 123123n;
    await sendIx(
      await initializeRelayer({
        admin: tempAdmin.publicKey,
        fee,
        payer: payer.publicKey,
        relayerDecryptionKey,
        relayerEndpoint,
        relayerFeeKey: relayer.publicKey,
      }),
    );

    const relayerConfig = await fetchRelayerConfig(connection);
    expect(relayerConfig?.admin.equals(tempAdmin.publicKey)).to.be.true;
    expect(toBigint(relayerConfig?.fee)).to.equal(fee);
    expect(relayerConfig?.relayer).to.deep.equal({
      decryptionKey: relayerDecryptionKey,
      feeKey: relayer.publicKey,
      endpoint: relayerEndpoint,
    });
  });

  test("updateRelayerConfig", async () => {
    const relayerDecryptionKey = {
      x: toBytesBE(relayerPK[0]),
      y: toBytesBE(relayerPK[1]),
    };
    const relayerEndpoint = "https://test2.test";
    await sendIx(
      await updateRelayerConfig({
        oldAdmin: tempAdmin.publicKey,
        newAdmin: admin.publicKey,
        fee: relayerFee,
        payer: payer.publicKey,
        relayerDecryptionKey,
        relayerEndpoint,
        relayerFeeKey: relayer.publicKey,
      }),
      [payer, tempAdmin],
    );

    const relayerConfig = await fetchRelayerConfig(connection);
    expect(relayerConfig?.admin.equals(admin.publicKey)).to.be.true;
    expect(toBigint(relayerConfig?.fee)).to.equal(relayerFee);
    expect(relayerConfig?.relayer).to.deep.equal({
      decryptionKey: relayerDecryptionKey,
      feeKey: relayer.publicKey,
      endpoint: relayerEndpoint,
    });
  });
});

describe("Anon Vote", () => {
  const tempAdmin = new Keypair();

  const pollId = 5n;
  let C_SK: bigint;
  let C_PKx: Uint8Array;
  let C_PKy: Uint8Array;
  const nChoices = 6;

  test("initialize", async () => {
    const fee = 789789n;
    const feeDestination = new Keypair().publicKey;

    await sendIx(
      await initialize({
        admin: tempAdmin.publicKey,
        fee,
        feeDestination,
        payer: payer.publicKey,
      }),
    );

    const platformConfig = await fetchPlatformConfig(connection);
    expect(platformConfig?.admin.equals(tempAdmin.publicKey)).to.be.true;
    expect(toBigint(platformConfig?.fee)).to.equal(fee);
    expect(platformConfig?.feeDestination.equals(feeDestination)).to.be.true;
  });

  test("updateConfig", async () => {
    await sendIx(
      await updateConfig({
        oldAdmin: tempAdmin.publicKey,
        newAdmin: admin.publicKey,
        fee: platformFee,
        feeDestination: platformFeeDestination.publicKey,
      }),
      [payer, tempAdmin],
    );

    const platformConfig = await fetchPlatformConfig(connection);
    expect(platformConfig?.admin.equals(admin.publicKey)).to.be.true;
    expect(toBigint(platformConfig?.fee)).to.equal(platformFee);
    expect(
      platformConfig?.feeDestination.equals(platformFeeDestination.publicKey),
    ).to.be.true;
  });

  test("createPoll", async () => {
    const { sk: sk_, PKx: C_PKx0, PKy: C_PKy0 } = await genBabyJubKeypair(
      babyjub,
    );
    C_SK = sk_;
    C_PKx = C_PKx0;
    C_PKy = C_PKy0;
    const coordinatorKey = {
      x: toBytesBE(F.toObject(C_PKx)),
      y: toBytesBE(F.toObject(C_PKy)),
    };

    const descriptionUrl =
      "https://ipfs.io/ipfs/bafkreicvkyr25sgsl2suwl4euwlexamplevyk7vxnai6tti2qexaexaexa";
    const censusUrl =
      "https://ipfs.io/ipfs/bafkreicvkyr25sgsl2suwl4euwlexamplevyk7vxnai6tti2qexaexaexa";
    const votingStartTime = new BN(Math.floor(Date.now() / 1000) + 1);
    const votingEndTime = new BN(Math.floor(Date.now() / 1000) + 15);
    await sendIx(
      await createPoll({
        payer: payer.publicKey,
        id: pollId,
        censusRoot: toBytesBE(CensusRoot),
        coordinatorKey,
        nChoices,
        votingStartTime,
        votingEndTime,
        fee: pollFee,
        feeDestination: pollFeeDestination.publicKey,
        nVoters: BigInt(N_VOTERS),
        descriptionUrl,
        censusUrl,
      }),
    );

    const poll = await fetchPoll(connection, findPoll(pollId));
    expect(toBigint(poll?.id)).to.equal(pollId);
    expect(poll?.nChoices).to.equal(nChoices);
    expect(poll?.coordinatorKey).to.deep.equal(coordinatorKey);
    expect(poll?.censusRoot).to.deep.equal(toBytesBE(CensusRoot));
    expect(poll?.runningMsgHash).to.deep.equal(
      Array.from({ length: 32 }, () => 0),
    );
    expect(poll?.votingStartTime.eq(votingStartTime)).to.be.true;
    expect(poll?.votingEndTime.eq(votingEndTime)).to.be.true;
    expect(toBigint(poll?.platformFee)).to.deep.equal(platformFee);
    expect(toBigint(poll?.fee)).to.equal(pollFee);
    expect(poll?.feeDestination.equals(pollFeeDestination.publicKey)).to.be
      .true;
    expect(poll?.descriptionUrl).to.equal(descriptionUrl);
    expect(poll?.censusUrl).to.equal(censusUrl);
    expect(poll?.tally).to.be.empty;

    const relayerState = await fetchRelayerState(
      connection,
      findRelayerState(PROGRAM_ID, pollId),
    );
    expect(relayerState?.endTime.eq(votingEndTime)).to.be.true;
    expect(toBigint(relayerState?.msgLimit)).to.equal(MSG_LIMIT);
    expect(relayerState?.root).to.deep.equal(
      Array.from({ length: 32 }, () => 0),
    );
  });

  test("vote", async () => {
    const N_choices = BigInt(nChoices);

    const PollId = pollId;

    const BatchLen = voters.length + 2;
    expect(BatchLen).to.be.lessThan(MAX_BATCH);

    const relayerDb = new InMemoryDB(new Uint8Array(1));
    const quotaMt = new Merkletree(relayerDb, true, STATE_DEPTH);
    const quotaMtMap = new Map();

    const prvSecondary = F.e(42n);
    const pubSecondary = eddsa.prv2pub(prvSecondary);

    for (let i = 0; i < BatchLen; i++) {
      const voterIndex = BatchLen > 2 && i >= BatchLen - 2
        ? voters.length - 1
        : i;
      const { prvPrimary, pubPrimary } = voters[voterIndex];
      const Nonce = 5n + BigInt(i);
      const M_N = poseidon([PLATFORM_NAME, PollId]);
      const sigN = eddsa.signPoseidon(prvPrimary, M_N);
      expect(eddsa.verifyPoseidon(M_N, sigN, pubPrimary)).to.be.true;

      const PrimarySignaturePoint = [
        F.toObject(sigN.R8[0]),
        F.toObject(sigN.R8[1]),
      ];
      const PrimarySignatureScalar = sigN.S;

      const sigHash = F.toObject(poseidon([
        PrimarySignatureScalar,
        PrimarySignaturePoint[0],
        PrimarySignaturePoint[1],
      ]));
      const Choice = BigInt((i % nChoices) + 1); // 1..nChoices

      const r = randomScalar(babyjub.subOrder);
      const Rraw = babyjub.mulPointEscalar(babyjub.Base8, r);
      const C_Sraw = babyjub.mulPointEscalar([C_PKx, C_PKy], r);
      const R: [bigint, bigint] = [F.toObject(Rraw[0]), F.toObject(Rraw[1])];
      const C_S: [bigint, bigint] = [
        F.toObject(C_Sraw[0]),
        F.toObject(C_Sraw[1]),
      ];

      // normal votes, then key change, then a valid vote with new key, then an invalid vote
      const SecondaryKeyOld = i == BatchLen - 2 && BatchLen > 2
        ? pubSecondary.map((x) => F.toObject(x))
        : [0n, 0n];
      const SecondaryKeyNew = i == BatchLen - 3 && BatchLen > 2
        ? pubSecondary.map((x) => F.toObject(x))
        : [42n, 42n];

      let SecondarySignaturePoint = [0n, 0n];
      let SecondarySignatureScalar = 0n;
      if (i == BatchLen - 2 && BatchLen > 2) {
        const M_N = poseidon([
          PLATFORM_NAME,
          sigHash,
          Choice,
          SecondaryKeyNew[0],
          SecondaryKeyNew[1],
        ]);
        const sigN = eddsa.signPoseidon(prvSecondary, M_N);

        SecondarySignaturePoint = [
          F.toObject(sigN.R8[0]),
          F.toObject(sigN.R8[1]),
        ];
        SecondarySignatureScalar = sigN.S;
      }

      const nuCoordinator = F.toObject(poseidon([sigHash]));
      const C_P = [
        nuCoordinator,
        Choice,
        SecondaryKeyOld[0],
        SecondaryKeyOld[1],
        SecondaryKeyNew[0],
        SecondaryKeyNew[1],
      ];
      const C_CT = poseidonEncrypt(C_P, C_S, Nonce);

      const C_LIMBS = C_P.length;
      const C_PAD = (C_LIMBS % 3 === 0)
        ? C_LIMBS
        : C_LIMBS + (3 - (C_LIMBS % 3));
      if (C_CT.length !== C_PAD + 1) {
        throw new Error(
          `CT length mismatch: got ${C_CT.length}, expected ${C_PAD + 1}`,
        );
      }

      let RelayerPK = [0n, 0n];
      let R_P = [0n];
      let R_CT = [0n, 0n, 0n, 0n];

      if (i == 1) {
        RelayerPK = relayerPK;
        const relayerNu = poseidon([sigHash, RelayerPK[0], RelayerPK[1]]);
        R_P = [F.toObject(relayerNu)];

        const R_Sraw = babyjub.mulPointEscalar([
          F.e(RelayerPK[0]),
          F.e(RelayerPK[1]),
        ], r);
        const R_S: [bigint, bigint] = [
          F.toObject(R_Sraw[0]),
          F.toObject(R_Sraw[1]),
        ];

        R_CT = poseidonEncrypt(R_P, R_S, Nonce);
      }

      const R_LIMBS = R_P.length;
      const R_PAD = (R_LIMBS % 3 === 0)
        ? R_LIMBS
        : R_LIMBS + (3 - (R_LIMBS % 3));
      if (R_CT.length !== R_PAD + 1) {
        throw new Error(
          `CT length mismatch: got ${R_CT.length}, expected ${R_PAD + 1}`,
        );
      }

      const CoordinatorPK = [F.toObject(C_PKx), F.toObject(C_PKy)];
      const { path, pathPos } = await getMerkleProof(
        CENSUS_DEPTH,
        census,
        voterIndex,
      );
      const inputs = {
        CensusRoot,
        PollId,
        N_choices,
        SecondaryKeyNew,
        SecondaryKeyOld,
        SecondarySignaturePoint,
        SecondarySignatureScalar,

        PrimaryKey: [F.toObject(pubPrimary[0]), F.toObject(pubPrimary[1])],
        PrimarySignaturePoint,
        PrimarySignatureScalar,

        Path: path,
        PathPos: pathPos,
        Choice,
        ephR: r,
        CoordinatorPK,
        RelayerPK,
        Nonce,
        C_CT,
        R_CT,
      };

      let { proof, publicSignals } = await groth16.fullProve(
        inputs,
        "build/Vote/Vote_js/Vote.wasm",
        "build/Vote/groth16_pkey.zkey",
      );

      const MsgHash_js = F.toObject(poseidon([R[0], R[1], Nonce, ...C_CT]));
      const R_CT_hash_js = i == 1 ? F.toObject(poseidon(R_CT)) : 0n;

      const MsgHash_pub = BigInt(publicSignals[0]);
      const R_CT_hash_pub = BigInt(publicSignals[1]);
      const CensusRoot_pub = BigInt(publicSignals[2]);
      const PollId_pub = BigInt(publicSignals[3]);
      const N_choices_pub = BigInt(publicSignals[4]);
      const PK_pub = [BigInt(publicSignals[5]), BigInt(publicSignals[6])];

      if (CensusRoot_pub !== CensusRoot) throw new Error("CensusRoot mismatch");
      if (PollId_pub !== PollId) throw new Error("PollId mismatch");
      if (MsgHash_pub !== MsgHash_js) throw new Error("MsgHash mismatch");
      if (R_CT_hash_pub !== R_CT_hash_js) throw new Error("R_CT_hash mismatch");
      if (N_choices_pub !== N_choices) throw new Error("N_choices mismatch");
      if (PK_pub[0] != CoordinatorPK[0] || PK_pub[1] != CoordinatorPK[1]) {
        throw new Error("PK mismatch");
      }

      const vkey = JSON.parse(
        readFileSync("./build/Vote/groth16_vkey.json", "utf8"),
      );
      expect(await groth16.verify(vkey, publicSignals, proof)).to.be.true;

      const serializedProof = compressProofForSolana(proof);

      const eventPromise: Promise<void> = new Promise((resolve, reject) => {
        onVote((event) => {
          try {
            expect(event.ciphertext).to.deep.equal(
              C_CT.map((x) => toBytesBE(x)),
            );
            expect(event.ephKey.x).to.deep.equal(toBytesBE(R[0]));
            expect(event.ephKey.y).to.deep.equal(toBytesBE(R[1]));
            expect(toBigint(event.nonce)).to.equal(Nonce);
            resolve();
          } catch (error) {
            reject(error);
          }
        });
        setTimeout(() => {
          reject(new Error("Event did not fire within timeout"));
        }, 12000);
      });

      if (i == 1) {
        const Root_before = (await quotaMt.root()).bigInt();

        const [relayerNu] = poseidonDecrypt(
          R_CT,
          mulPointEscalar(R, R_SK),
          Nonce,
          R_LIMBS,
        );
        const idx = relayerNu & ((1n << BigInt(STATE_DEPTH)) - 1n);

        const PrevCount = quotaMtMap.get(idx) ?? 0;
        quotaMtMap.set(idx, PrevCount + 1);

        let proofQuota: CircomProcessorProof | CircomVerifierProof;
        try {
          proofQuota = await quotaMt.addAndGetCircomProof(
            idx,
            BigInt(PrevCount + 1),
          );
        } catch (e) {
          if (e != ErrEntryIndexAlreadyExists) {
            throw e;
          }

          proofQuota = await quotaMt.update(idx, BigInt(PrevCount + 1));
        }

        const proofUniq = await quotaMt.addAndGetCircomProof(MsgHash_pub, 1n);

        const SiblingsQuota = proofQuota.siblings.map((h) => h.bigInt());
        expect(SiblingsQuota.length).to.equal(STATE_DEPTH);
        const SiblingsUniq = proofUniq.siblings.map((h) => h.bigInt());
        expect(SiblingsUniq.length).to.equal(STATE_DEPTH);

        const MsgLimit = 3n;

        const inputs = {
          Root_before,
          MsgHash: MsgHash_js,
          MsgLimit,
          SK: R_SK,
          EphKey: R,
          Nonce,
          CT: R_CT,
          PrevCount: BigInt(PrevCount),
          SiblingsQuota,
          NoAuxQuota: BigInt(proofQuota.isOld0),
          AuxKeyQuota: proofQuota.oldKey.bigInt(),
          AuxValueQuota: proofQuota.oldValue.bigInt(),
          SiblingsUniq,
          NoAuxUniq: BigInt(proofUniq.isOld0),
          AuxKeyUniq: proofUniq.oldKey.bigInt(),
          AuxValueUniq: proofUniq.oldValue.bigInt(),
        };

        const { proof: relayerProof, publicSignals } = await groth16.fullProve(
          inputs,
          "build/Relay/Relay_js/Relay.wasm",
          "build/Relay/groth16_pkey.zkey",
        );

        const Root_after = BigInt(publicSignals[0]);
        const R_CT_hash_pub = BigInt(publicSignals[1]);
        const Root_before_pub = BigInt(publicSignals[2]);
        const MsgHash_pubRelayer = BigInt(publicSignals[3]);
        const MsgLimit_pub = BigInt(publicSignals[4]);
        const EphKeyX_pub = BigInt(publicSignals[5]);
        const EphKeyY_pub = BigInt(publicSignals[6]);
        const Nonce_pub = BigInt(publicSignals[7]);

        expect(Root_after).to.equal((await quotaMt.root()).bigInt());
        expect(R_CT_hash_pub).to.equal(R_CT_hash_js);
        expect(Root_before_pub).to.equal(Root_before);
        expect(MsgHash_pubRelayer).to.equal(MsgHash_js);
        expect(MsgLimit_pub).to.equal(MsgLimit);
        expect(EphKeyX_pub).to.equal(R[0]);
        expect(EphKeyY_pub).to.equal(R[1]);
        expect(Nonce_pub).to.equal(Nonce);

        const vkey = JSON.parse(
          readFileSync("build/Relay/groth16_vkey.json", "utf8"),
        );
        const ok = await groth16.verify(vkey, publicSignals, relayerProof);
        expect(ok).to.equal(true);

        const serializedRelayerProof = compressProofForSolana(relayerProof);

        await sendIx(
          await voteWithRelayer({
            relayer: relayer.publicKey,
            pollId,
            msgHash: toBytesBE(MsgHash_js),
            ciphertext: C_CT.map((x) => toBytesBE(x)),
            ephKey: { x: toBytesBE(R[0]), y: toBytesBE(R[1]) },
            nonce: Nonce,
            proof: {
              a: Array.from(serializedProof.a),
              b: Array.from(serializedProof.b),
              c: Array.from(serializedProof.c),
            },
            platformFeeDestination: platformFeeDestination.publicKey,
            relayerCiphertextHash: toBytesBE(R_CT_hash_js),
            relayerProof: {
              a: Array.from(serializedRelayerProof.a),
              b: Array.from(serializedRelayerProof.b),
              c: Array.from(serializedRelayerProof.c),
            },
            rootAfter: toBytesBE(Root_after),
          }),
          [relayer],
        );
      } else {
        await sendIx(
          await vote({
            payer: payer.publicKey,
            pollId,
            ciphertext: C_CT.map((x) => toBytesBE(x)),
            ephKey: { x: toBytesBE(R[0]), y: toBytesBE(R[1]) },
            nonce: Nonce,
            proof: {
              a: Array.from(serializedProof.a),
              b: Array.from(serializedProof.b),
              c: Array.from(serializedProof.c),
            },
            platformFeeDestination: platformFeeDestination.publicKey,
            pollFeeDestination: pollFeeDestination.publicKey,
          }),
        );
      }
      await eventPromise;
      messages.push({
        ephKey: R,
        nonce: Nonce,
        ciphertext: C_CT,
      });
    }

    // writeProofBin(proof, "proof.bin");
    // writePublicInputsBin(publicSignals, "public_inputs.bin");
    // writeVkBin("./build/Vote/groth16_vkey.json", "vk.bin");
  });

  const MAX_BATCH = 6;
  const LIMBS = 6;
  const MAX_CHOICES = 8;

  it("tally", async () => {
    const db = new InMemoryDB(new Uint8Array());
    const mt = new Merkletree(db, true, STATE_DEPTH);
    const mtMap = new Map();
    const Root_before = (await mt.root()).bigInt();
    expect(Root_before).to.equal(0n);

    let curRoot = Root_before;
    const H_before = 0n;
    let H = H_before;
    const Tally_before = Array<bigint>(MAX_CHOICES).fill(0n);
    const tally = Tally_before.slice();

    const TallySalt_before = 42n;
    const TallySalt_after = 43n;
    const TallyHash_before = F.toObject(
      poseidon([TallySalt_before, ...Tally_before]),
    );

    const EphKey: bigint[][] = [];
    const Nonce: bigint[] = [];
    const CT: bigint[][] = [];
    const Siblings: bigint[][] = [];
    const PrevChoice: bigint[] = [];
    const IsPrevEmpty: bigint[] = [];
    const NoAux: bigint[] = [];
    const AuxKey: bigint[] = [];
    const AuxValue: bigint[] = [];
    const SecondaryKeyOldActual: bigint[][] = [];

    for (const message of messages) {
      const [
        nu,
        choice,
        secondaryKeyOldFromMsg0,
        secondaryKeyOldFromMsg1,
        secondaryKeyNew0,
        secondaryKeyNew1,
      ] = poseidonDecrypt(
        message.ciphertext,
        mulPointEscalar(message.ephKey, C_SK),
        message.nonce,
        LIMBS,
      );

      const idx = nu & ((1n << BigInt(STATE_DEPTH)) - 1n);

      const secondaryKeyNew = [secondaryKeyNew0, secondaryKeyNew1];

      const prevLeaf = mtMap.get(idx) ?? {
        choice: 0n,
        secondaryKey: [0n, 0n],
      };
      const voteIsValid = prevLeaf.secondaryKey[0] == secondaryKeyOldFromMsg0 &&
        prevLeaf.secondaryKey[1] == secondaryKeyOldFromMsg1;
      if (voteIsValid) {
        mtMap.set(idx, { choice, secondaryKey: secondaryKeyNew });
      }
      const leaf = F.toObject(
        poseidon([choice, secondaryKeyNew[0], secondaryKeyNew[1]]),
      );
      let proof: CircomProcessorProof | CircomVerifierProof;
      if (voteIsValid) {
        try {
          proof = await mt.addAndGetCircomProof(idx, leaf);
          IsPrevEmpty.push(1n);
        } catch (e) {
          if (e != ErrEntryIndexAlreadyExists) {
            throw e;
          }

          proof = await mt.update(idx, leaf);
          IsPrevEmpty.push(0n);
        }
      } else {
        proof = await mt.generateCircomVerifierProof(idx, ZERO_HASH);
        IsPrevEmpty.push(0n);
      }

      NoAux.push(BigInt(proof.isOld0));
      AuxKey.push(proof.oldKey.bigInt());
      AuxValue.push(proof.oldValue.bigInt());

      const siblings = proof.siblings.map((h) => h.bigInt());
      expect(siblings.length).to.equal(STATE_DEPTH);

      EphKey.push(message.ephKey);
      Nonce.push(message.nonce);
      CT.push(message.ciphertext);
      Siblings.push(siblings);
      PrevChoice.push(prevLeaf.choice);
      SecondaryKeyOldActual.push(prevLeaf.secondaryKey);

      const msgHash = F.toObject(
        poseidon([
          message.ephKey[0],
          message.ephKey[1],
          message.nonce,
          ...message.ciphertext,
        ]),
      );
      H = F.toObject(poseidon([H, msgHash]));

      if (voteIsValid) {
        curRoot = (await mt.root()).bigInt();
        if (prevLeaf.choice !== 0n) tally[Number(prevLeaf.choice) - 1] -= 1n;
        tally[Number(choice) - 1] += 1n;
      }
    }

    while (EphKey.length < MAX_BATCH) {
      EphKey.push(EphKey[EphKey.length - 1]);
      Nonce.push(Nonce[Nonce.length - 1]);
      CT.push(CT[CT.length - 1]);
      Siblings.push(Siblings[Siblings.length - 1]);
      PrevChoice.push(PrevChoice[PrevChoice.length - 1]);
      IsPrevEmpty.push(IsPrevEmpty[IsPrevEmpty.length - 1]);
      NoAux.push(NoAux[NoAux.length - 1]);
      AuxKey.push(AuxKey[AuxKey.length - 1]);
      AuxValue.push(AuxValue[AuxValue.length - 1]);
      SecondaryKeyOldActual.push(
        SecondaryKeyOldActual[SecondaryKeyOldActual.length - 1],
      );
    }

    const inputs = {
      Root_before,
      H_before: 0n,
      TallyHash_before,
      TallySalt_before,
      TallySalt_after,
      Tally_before,
      BatchLen: BigInt(messages.length),
      SK: C_SK,
      EphKey,
      Nonce,
      CT,
      Siblings,
      PrevChoice,
      SecondaryKeyOldActual,
      NoAux,
      AuxKey,
      AuxValue,
      IsPrevEmpty,
    };

    const { proof, publicSignals } = await groth16.fullProve(
      inputs,
      "build/Tally/Tally_js/Tally.wasm",
      "build/Tally/groth16_pkey.zkey",
    );

    const Root_after = BigInt(publicSignals[0]);
    const H_after = BigInt(publicSignals[1]);
    const TallyHash_after = BigInt(publicSignals[2]);
    expect(BigInt(publicSignals[3])).to.equal(Root_before);
    expect(BigInt(publicSignals[4])).to.equal(H_before);
    expect(BigInt(publicSignals[5])).to.equal(TallyHash_before);

    expect(Root_after).to.equal(curRoot);
    expect(H_after).to.equal(H);
    expect(TallyHash_after).to.equal(
      F.toObject(poseidon([TallySalt_after, ...tally])),
    );

    const vkey = JSON.parse(
      readFileSync("build/Tally/groth16_vkey.json", "utf8"),
    );
    const ok = await groth16.verify(vkey, publicSignals, proof);
    expect(ok).to.equal(true);

    await sendIx(
      await createTally({
        initialTallyHash: toBytesBE(TallyHash_before),
        payer: payer.publicKey,
        pollId,
      }),
    );

    const tallyAcc = await fetchTally(
      connection,
      findTally(pollId, payer.publicKey),
    );
    expect(tallyAcc?.tallyHash).to.deep.equal(toBytesBE(TallyHash_before));
    expect(tallyAcc?.runningMsgHash).to.deep.equal(
      Array.from({ length: 32 }, () => 0),
    );
    expect(tallyAcc?.root).to.deep.equal(Array.from({ length: 32 }, () => 0));

    await sendIx(
      await closeTally({
        owner: payer.publicKey,
        pollId,
      }),
    );

    expect(await fetchTally(connection, findTally(pollId, payer.publicKey))).to
      .be.null;

    await sendIx(
      await createTally({
        initialTallyHash: toBytesBE(TallyHash_before),
        payer: payer.publicKey,
        pollId,
      }),
    );

    await expect(sendIx(
      await finishTally({
        pollId,
        payer: payer.publicKey,
        tally: tally.slice(0, nChoices),
        tallySalt: TallySalt_after,
      }),
    )).to.rejectedWith("IncorrectTally");

    const serializedProof = serProof(proof, true);
    await sendIx(
      await tallyBatch({
        pollId,
        proof: {
          a: Array.from(serializedProof.a),
          b: Array.from(serializedProof.b),
          c: Array.from(serializedProof.c),
        },
        owner: payer.publicKey,
        rootAfter: toBytesBE(Root_after),
        runningMsgHashAfter: toBytesBE(H_after),
        tallyHashAfter: toBytesBE(TallyHash_after),
      }),
    );

    const fakeTally = tally.slice(0, nChoices);
    fakeTally[0] += 1n;
    await expect(sendIx(
      await finishTally({
        pollId,
        payer: payer.publicKey,
        tally: fakeTally,
        tallySalt: TallySalt_after,
      }),
    )).to.rejectedWith("IncorrectTally");

    await sendIx(
      await finishTally({
        pollId,
        payer: payer.publicKey,
        tally: tally.slice(0, nChoices),
        tallySalt: TallySalt_after,
      }),
    );

    expect(await fetchTally(connection, findTally(pollId, payer.publicKey))).to
      .be.null;

    const poll = await fetchPoll(connection, findPoll(pollId));
    expect(poll?.tally.map(toBigint)).to.deep.equal(tally.slice(0, nChoices));
  });

  test("withdrawPoll", async () => {
    await sendIx(
      await withdrawPoll({
        id: pollId,
        feeDestination: pollFeeDestination.publicKey,
      }),
    );
  });
});
