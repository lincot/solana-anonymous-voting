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

or with the indexer:

```sh
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'
```

```sh
anchor build
solana-test-validator \
  --reset \
  --warp-slot 32 \
  --deactivate-feature 9LZdXeKGeBV6hRLdxS1rHbHoEUsKqesCC2ZAPTPKJAbK \
  --bpf-program target/deploy/anon_vote-keypair.json target/deploy/anon_vote.so \
  --bpf-program target/deploy/zk_relayer-keypair.json target/deploy/zk_relayer.so

cargo run --package anon-vote-indexer -- --config indexer/config.yml

anchor test --skip-local-validator --skip-deploy
```

## compiling relayer backend

```sh
mkdir build/Relay/Relay_cpp/cpp_dat
cp build/Relay/Relay_cpp/Relay.* build/Relay/Relay_cpp/cpp_dat/
cd relayer
cargo test
```
