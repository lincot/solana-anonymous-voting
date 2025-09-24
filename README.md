# anonymous bribery-resistant voting on Solana

## first off

```sh
pnpm install
```

## compiling the circuits

For things to work, replace `Poseidon` with `PoseidonHasher` in
`node_modules/.pnpm/circomlib@2.0.5/node_modules/circomlib/circuits/smt/smthash_poseidon.circom`
and remove `../poseidon.circom` import.

```sh
pnpm circomkit compile Vote && pnpm circomkit setup Vote
pnpm circomkit compile Tally && pnpm circomkit setup Tally
pnpm circomkit compile Relay && pnpm circomkit setup Relay
```

Export verifying key (to put in `programs/anon-vote/src/vk.rs` and
`programs/zk-relayer/src/vk.rs`)

```sh
pnpm exportVk
```

## testing

```sh
anchor test
```
