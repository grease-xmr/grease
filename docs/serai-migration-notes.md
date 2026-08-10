# Serai / monero-oxide migration notes

Findings from the K-25 dependency spike. Every claim below was produced by actually resolving and
compiling the candidate dependency graph in a scratch branch, or by reading the upstream sources at
the exact revisions named; nothing here is inferred from release notes. Items that could not be
verified are marked **UNVERIFIED**.

The scratch swap itself was reverted — only this document landed. It is the input to the flag-day
ticket (K-26) and the sweep that follows it (K-27).

## Background

`libgrease` currently pins the serai monorepo at `dc1b8dfccd68b7c2eb4359a1e37b55ce5e4453b5`, which
predates two upstream reorganisations:

1. The Monero code was extracted out of serai into its own repository,
   [monero-oxide](https://github.com/monero-oxide/monero-oxide). `monero-serai` became
   `monero-oxide`, the `monero-rpc` crate was split into `monero-interface` +
   `monero-daemon-rpc`, and `monero-wallet` went 0.1 → 0.2.
2. serai's `next` branch rewrote the `ciphersuite` trait hierarchy, moved MuSig out of
   `modular-frost` into a standalone crate, and moved the whole crypto tree onto the
   RustCrypto `digest` 0.11 generation.

Neither change is available on crates.io as a coherent set, so both dependencies must be pinned by
git revision.

## 1. The revision pair

**Both repositories resolve and build together at their current `HEAD`s. The fallback rule was not
triggered.**

| Repository | Branch | Revision |
| --- | --- | --- |
| `https://github.com/serai-dex/serai.git` | `next` | `c31a2d4710684af4abdcc146a41f41fa35e229a5` |
| `https://github.com/monero-oxide/monero-oxide` | `main` | `731657ae3385be667abb556266369a497bc86f13` |

Method: started from serai `next`'s own monero-oxide pin
(`c8be5d3d1287669946a83fbfcb296ce2a8852e47`, used by `processor/monero` and
`substrate/client/monero`), then moved both to current `HEAD` and re-resolved. `cargo update`,
`cargo metadata` and `cargo check` all succeed on the `HEAD` pair, so the newer pin is preferred.

Relevant upstream versions at those revisions:

| Crate | Version | Source |
| --- | --- | --- |
| `ciphersuite` | 0.4.2 | serai `crypto/ciphersuite` |
| `dalek-ff-group` | 0.5.0 | serai `crypto/dalek-ff-group` |
| `flexible-transcript` | 0.3.4 | serai `crypto/transcript` |
| `modular-frost` | 0.11.0 | serai `crypto/frost` |
| `dkg` | 0.6.1 | serai `crypto/dkg` |
| `musig` | 0.6.0 | serai `crypto/dkg/musig` |
| `multiexp` | 0.4.2 | serai `crypto/multiexp` |
| `std-shims` | 0.1.5 | serai `common/std-shims` |
| `monero-oxide` | 0.1.0 | monero-oxide |
| `monero-wallet` | 0.2.0 | monero-oxide |
| `monero-interface` | 0.2.0 | monero-oxide |
| `monero-daemon-rpc` | 0.2.0 | monero-oxide |
| `monero-simple-request-rpc` | 0.1.0 | monero-oxide |
| `monero-address` | 0.1.0 | monero-oxide |
| `monero-clsag` | 0.1.0 | monero-oxide |

### A resolution trap: ambiguous package names in the serai repo

serai's tree contains *two* packages named `ciphersuite` (`crypto/ciphersuite` 0.4.2 and the compat
shim `patches/ciphersuite` 0.4.99) and *two* named `std-shims` (`common/std-shims` 0.1.5 and
`patches/std-shims` 0.1.99). A git dependency or patch entry that does not pin an exact version
fails with:

```
error: patch for `ciphersuite` in `https://github.com/serai-dex/serai.git?rev=…`
resolved to more than one candidate
note: found versions: 0.4.2, 0.4.99
```

Use `version = "=0.4.2"` and `version = "=0.1.5"` on those two entries. grease wants the real
crates, not the `patches/` shims — the shims exist to paper over upstream crates that have not yet
moved to the new `ciphersuite` API, and grease is moving.

## 2. The `[patch.crates-io]` closure

monero-oxide depends on serai's crypto crates *by crates.io version*, so without a patch closure
cargo resolves two disjoint families — one from crates.io, one from the git pin — and the
`Ed25519`/`ThresholdKeys`/`Preprocess` types from the two families do not unify.

Verified experimentally: with no patch section, `cargo tree -d -p libgrease` reports
`ciphersuite` 0.4.2 twice, `dalek-ff-group` 0.5.0 twice, `flexible-transcript` 0.3.4 twice,
`std-shims` three times, `modular-frost` 0.11.0 (git) alongside 0.11.1 (crates.io), and `multiexp`
0.4.2 (git) alongside 0.5.1 (crates.io).

**The minimal sufficient closure is four entries**, verified by removing each candidate and
re-resolving from a deleted lockfile:

```toml
[patch.crates-io]
std-shims           = { version = "=0.1.5", git = "https://github.com/serai-dex/serai.git", rev = "c31a2d47…" }
flexible-transcript = { version = "0.3",    git = "https://github.com/serai-dex/serai.git", rev = "c31a2d47…" }
dalek-ff-group      = { version = "0.5",    git = "https://github.com/serai-dex/serai.git", rev = "c31a2d47…" }
modular-frost       = { version = "0.11",   git = "https://github.com/serai-dex/serai.git", rev = "c31a2d47…" }
```

`ciphersuite`, `multiexp`, `dkg`, `schnorr-signatures` and `dkg-musig` do **not** need patch
entries: nothing in the graph reaches them from crates.io once `modular-frost` is patched, because
`modular-frost` reaches them through path dependencies inside the same git checkout, which cargo
treats as the same source. The four crates in the table above are exactly the ones monero-oxide
names as crates.io dependencies. (K-26's draft body lists a nine-entry closure including
`ciphersuite`, `schnorr-signatures`, `dkg`, `dkg-musig` and `multiexp` — that set resolves too, it
is just larger than necessary.)

After patching, `cargo tree -d -p libgrease` shows exactly one copy of `modular-frost`,
`ciphersuite`, `dalek-ff-group`, `flexible-transcript`, `multiexp`, `dkg`, `std-shims`,
`curve25519-dalek`, `rand_core`, `blake2` and `zeroize`.

## 3. Hash-crate generation: what actually duplicates

`digest` 0.10 and `digest` 0.11 **both remain in the graph, unavoidably**, and the same is true of
`sha2` 0.10 and 0.11:

- `digest` 0.10.7 arrives via `curve25519-dalek` 4.1.3, which both `dalek-ff-group` 0.5 and every
  monero-oxide crate depend on. `curve25519-dalek` has no 0.11-generation release.
- `sha2` 0.10.9 arrives via `ic-vetkeys` (EP-1's vetKD dependency), its transitive `ic_principal`,
  and `digest_auth` (used by `monero-simple-request-rpc`).
- `digest` 0.11.3 / `sha2` 0.11.0 arrive via `ciphersuite` and `dalek-ff-group`.

**K-26's acceptance criterion "exactly one version of every dependency … digest" is not
achievable and must be amended.** The one-version-per-dependency invariant holds for the
FROST/ciphersuite/transcript family and for `curve25519-dalek`, `rand_core`, `blake2` and
`zeroize`; it does not and cannot hold for `digest` and `sha2`.

The residual duplicate list after the swap, for the record (none of them are new problems, and all
belong to other dependency trees): `block-buffer`, `const-oid`, `cpufeatures`, `crypto-bigint`,
`crypto-common`, `digest`, `heck`, `hex-literal`, `sha2`, `strum`, `strum_macros`, `syn`,
`thiserror`.

### The one place the dual generation bites

`libgrease/src/cryptography/attestation.rs:263`:

```rust
let point = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(input, HASH_TO_G1_AUG_DST);
```

`ic_bls12_381` 0.10 states `ExpandMsgXmd<H>`'s bound in **digest 0.10** traits. Once `sha2` moves to
0.11 its `Sha256` no longer satisfies them:

```
error[E0277]: the trait bound `Sha256: curve25519_dalek::digest::FixedOutput` is not satisfied
error[E0277]: the trait bound `Sha256: curve25519_dalek::digest::HashMarker` is not satisfied
```

This is the only design decision the hash bump forces. The cheapest fix is to keep a second,
renamed 0.10-generation `sha2` (`sha2_010 = { package = "sha2", version = "0.10" }`) for that single
line; the 0.10 crate is already in the graph so it costs nothing. Whichever route is taken must be
byte-identical, because `src/tests/vetkd_compat_vectors.rs` freezes the `ExpandMsgXmd<Sha256>`
outputs.

`Sha512` in the same file is unaffected — it is only used through `Digest`, which is generation-clean.

### Everything else in the hash bump is mechanical

Full call-site catalog, all of which type-check unchanged under the 0.11 generation:
`digest::consts`, `digest::typenum`, `digest::OutputSizeUser`, `Digest::new`, `chain_update`,
`finalize`, `Digest::digest`, `Blake2b512`, `Blake2b<U32>`, and both
`Output<Sha512> -> [u8; 64]` `.into()` conversions in `binding_proof.rs`. There is no
`GenericArray`, `core_api`, `hmac`/`Mac`, `Blake2bVar` or `new_with_prefix` usage anywhere in
`libgrease`.

`sha3` is a `libgrease` dev-dependency with **zero references** in the workspace. Drop it rather
than bumping it.

## 4. Frozen vectors: what survives and what moves

This is the part EP-1 and K-24 care about. Verified by building a standalone probe crate against
the new pins and running it.

### Survives byte-for-byte

- **`hash_to_F(dst, msg)`.** The removed `ciphersuite 0.4.1` method was, for the dalek curves,
  literally `Scalar::from_hash(Sha512::new_with_prefix([dst, data].concat()))`. The replacement
  `WithPreferredHash::hash_to_F(data)` is `F::from_uniform_bytes(Sha512(data))`, and for
  `curve25519_dalek::Scalar` `from_uniform_bytes` *is* `from_bytes_mod_order_wide`. So a one-line
  grease-side helper

  ```rust
  fn hash_to_F<C: WithPreferredHash>(dst: &[u8], msg: &[u8]) -> C::F {
      C::hash_to_F([dst, msg].concat())
  }
  ```

  reproduces the old output exactly. Checked equal on three of grease's real domain tags
  (`GREASE-PVSS-PRF-v1`, `SchnorrPoK`, `AdaptedSignature-challenge`). All seven `hash_to_F` call
  sites in `libgrease` are therefore mechanical, and the PVSS, Schnorr PoK, adaptor-signature and
  ECDH vectors are unaffected.

- **`flexible-transcript`'s `DigestTranscript` framing.** 0.3.0 → 0.3.4 kept the member tag bytes
  (`Name`=0 … `Challenged`=6), the `u64` little-endian length prefix on every append, and the
  clone-and-fork construction in `challenge()`. `RecommendedTranscript` is still Blake2b512 — it is
  now `DigestTranscript<ZeroizeOnDropBlake2b512>` rather than `DigestTranscript<Blake2b512>`, but
  upstream carries its own test asserting the two hash identically. The *type* changed; the bytes
  did not. EP-1 and K-24 transcript vectors are safe.

- **`blake2` 0.10.6 → 0.11.0-rc.** The probe reproduced K-24's `musig_dh_viewkey_is_frozen`
  vectors exactly (`bc26e2b8…27c27c09` / `98d67ed9…ec49bec8`) and the frozen public keys
  `616e2377…43e8bdcf` / `af6302f1…b3d059bf`.

### Moves — the MuSig joint spend key

`modular_frost::dkg::musig::musig` no longer exists. Its replacement is the standalone crate
**`musig` 0.6.0** (serai `crypto/dkg/musig`) — note the package is named `musig`, not `dkg-musig`
as K-26's draft assumed. Two changes to the binding-factor transcript make the aggregated key
different:

| | frost 0.8 `dkg::musig` | `musig` 0.6.0 |
| --- | --- | --- |
| context | `&[u8]`, framed as `len_u8 ‖ context` | fixed `[u8; 32]`, no length prefix |
| binding factor | `C::hash_to_F(b"musig", transcript)` | `F::from_uniform_bytes(C::H::digest(transcript))` — **no DST** |
| signature | `musig(&ctx, &Zeroizing<F>, &keys) -> Result<ThresholdCore<C>, DkgError<()>>` | `musig(ctx, Zeroizing<F>, &keys) -> Result<ThresholdKeys<C>, MusigError<C>>` |
| secret share | private key × binding factor, divided by the Lagrange factor | private key as-is, with `Interpolation::Constant(binding_factors)` |

The group key is still `Σ bᵢ·Pᵢ` with `bᵢ` derived from `(context, n, keys, i)`, so the scheme is
unchanged; only the transcript preimage moved.

grease passes a 69-byte context, `"Musig" ‖ P_A ‖ P_B` (`musig_context` in
`payment_channel/multisig_keyring.rs`), which no longer fits. **Recommendation: compress it with
`Blake2b512(context)[..32]`** — grease already uses Blake2b512 everywhere else for this kind of
derivation, and it keeps the full 69 bytes bound.

Under that rule, over K-24's frozen key pair, the joint spend key moves:

```
2be132dccafba6aa928022244be1a8ddb707c7ac5c49653d530bf8f98b3ce1c3   (frost 0.8)
d84486c8b988b72aacee390bb88bde734332d4c06a383f27874428f833ad7319   (musig 0.6.0, blake2b512-first-32 context)
```

Verified from both parties' sides and against `musig_key_vartime`. For reference, a `Sha512`-based
compression would instead give `25b1e50b135dab1a54edee478d955821869fcdb5cbbc7cef317563acbdbcc68f`.

**Every channel's 2-of-2 joint spend key therefore changes.** Grease is a proof of concept with no
live channels, so the cost is confined to the frozen vectors, but this is a hard wire-format break
and must be called out explicitly rather than slipped in. Two K-24 tests must be updated in the
same commit as the swap:

- `payment_channel/multisig_keyring.rs::musig_group_key_is_frozen`
- `wallet/multisig_wallet.rs::deterministic_rng_stream_is_frozen` (it asserts the joint spend key
  as an intermediate, and its ChaCha20 stream is derived from the joint *view* key, which does not
  move — but the spend-key assertion in it does)

## 5. `WalletOutput` 0.1 → 0.2: **breaking, but mechanically migratable**

Diffed `write()`/`read()` field by field across the two trees.

Byte-identical: `OutputData` (32-byte compressed key ‖ 32-byte scalar ‖ 40-byte `Commitment`),
`Commitment`, `Timelock`, `PaymentId`, `SubaddressIndex` as embedded in `Metadata`, `RelativeId`.
The new `ed25519::Scalar::write` and `CompressedPoint::write` still emit 32 raw little-endian bytes
with no prefix or tag.

Two changes:

| Field | 0.1 | 0.2 | Delta |
| --- | --- | --- | --- |
| `AbsoluteId.index_in_transaction` | `u32` LE (4 bytes) | `u64` LE (8 bytes) | +4 |
| `Metadata.arbitrary_data` count | `u32` LE (4 bytes) | varint | −3 for the common count of 0 |

Both are positionally unambiguous, so a read shim over the old layout is straightforward: read the
old blob with a hand-written reader that widens the `u32` index and re-frames the count, then write
it back out through `WalletOutput::write`. Nothing needs to be re-derived from the chain.

`grease` persists these blobs in three places, all in `wallet/`: `helpers::serialize_outputs` /
`deserialize_outputs` (serde), `MultisigWallet::save_outputs` / `load_outputs` (raw file), and
`MultisigWallet::read_outputs`. K-23's fixture is the tripwire and **will go red** — that is
correct behaviour, not a regression.

Related, and worse if grease ever persists it: `Decoys::write` lost the varint length prefix on the
ring (`write_vec` → `write_raw_vec`, count now inferred from `offsets.len()`), so
`OutputWithDecoys` blobs are also incompatible. grease does not currently persist
`OutputWithDecoys`, so this is informational.

### Resolution (K-26)

A read shim, not a re-scan. `wallet::helpers::read_output` parses the 0.2 layout and, on failure, rewrites an 0.1
record into it — widening `index_in_transaction` and reframing the `arbitrary_data` count — then re-writes through
`WalletOutput::write`, so a migrated output round-trips natively from then on. All four persistence entry points go
through it: `helpers::deserialize_outputs`, `MultisigWallet::load`, `MultisigWallet::read_outputs` and
`import_output`. `MultisigWallet::load` reads a run of records with no delimiter, so it now reads the file whole and
peels one record at a time rather than looping until a read fails.

The caveat, on the record: neither layout is self-describing and neither carries a version tag, so the fallback is
decided by whether the 0.2 reader fails. An old record is one field width out of alignment from its second field
onwards, which all but guarantees an invalid key or a non-canonical scalar — but the discrimination is probabilistic,
not tagged. It is documented as such at the call site.

The tripwire above did not exist: K-23 added no fixture and nothing in the repo persists a `WalletOutput` blob, so
the shim's four tests were written from scratch. They assemble a blob field by field in both layouts and assert the
migrated record equals the natively parsed one, including a two-chunk `arbitrary_data` case so the varint reframing
is exercised rather than only the zero count.

## 6. API drift catalog

Everything below was produced from real compiler errors against the new pins, not from reading
changelogs. The first `cargo check -p libgrease --all-features --all-targets` on unmodified sources
reports **85 errors across 22 files**; once the import layer is unblocked the count rises to
**~182**, because later phases become reachable.

### Type identity changes (pervasive, easy to miss)

- **`dalek_ff_group::Scalar` is now a re-export of `curve25519_dalek::Scalar`, not a newtype.**
  Every `XmrScalar(x)` construction and every `.0` field access on a scalar breaks, and
  `impl From<XmrScalar> for Curve25519Secret` now *conflicts* with
  `impl From<curve25519_dalek::Scalar> for Curve25519Secret` (E0119) — one of the two must go.
  `dalek_ff_group::EdwardsPoint` **is** still a newtype, so `XmrPoint(p)` and `.0` still work there.
- **`monero-oxide` introduced its own `ed25519::Point` / `ed25519::Scalar` wrappers.** The wallet
  API (`ViewPair::new`, `OutputWithDecoys::key()`, `WalletOutput::key_offset()`) speaks those, not
  `curve25519_dalek` types. Conversions are `Point::from(..)` / `.into()` in both directions.
- `zeroize` 1.8.1 → 1.8.2 made `Zeroizing`'s field private. Five `.0` accesses in `libgrease` must
  become derefs. This is incidental to the swap but lands with it.

### `ciphersuite` 0.4.1 → 0.4.2

The `Ciphersuite` trait was split into `WrappedGroup` (associated `F`/`G`, `generator()`), `Id`,
`WithPreferredHash` (`H`, `hash_to_F`), `GroupCanonicalEncoding` and `GroupIo`, with `Ciphersuite`
becoming a blanket-implemented alias over them.

| Was | Now |
| --- | --- |
| `use ciphersuite::Ed25519` | `use dalek_ff_group::Ed25519` |
| `C::G`, `C::F` | same, but `WrappedGroup` must be in scope |
| `C::generator()` | `<C as WrappedGroup>::generator()` |
| `C::hash_to_F(dst, msg)` | grease-side helper, see §4 |
| `C::random_nonzero_F(rng)` | **removed** — grease must implement it (a 5-line rejection loop) |

Ten `Ed25519::generator()` sites across `pvss.rs`, `binding_proof.rs` and
`grease_protocol/establish_channel.rs`.

### `flexible-transcript` 0.3.0 → 0.3.4

`SecureDigest` was **deleted**; `DigestTranscript<D>` is now bounded on plain `D: Send + Clone +
Digest`. grease uses `SecureDigest` as a bound in 16 places across `commit.rs`, `channel_id.rs` and
`grease_protocol/multisig_wallet.rs`, and the `>= 32 bytes` guarantee it carried is load-bearing
for the `copy_from_slice(&commitment[0..32])` at `grease_protocol/multisig_wallet.rs:213`. **grease
must re-declare the trait locally** (the original is nine lines over `digest::typenum`), not
replace it with plain `Digest`. Note `channel_id.rs` spells the same bound three more times as
`<D as OutputSizeUser>::OutputSize: IsGreaterOrEqual<U32, Output = True>`; unify on one spelling.

`Zeroize` is no longer implemented for `DigestTranscript<D>` in general — only for
`RecommendedTranscript`, via a shim upstream marks `TODO: Remove after monero-oxide updates`. If
grease relies on it for another digest, it needs its own.

### `modular-frost` 0.8 → 0.11

Largely source-compatible. `Participant`, `ThresholdKeys`, `ThresholdParams`, `ThresholdView`,
`Preprocess`, `SignatureShare`, `Writable`, `PreprocessMachine`, `SignMachine`, `SignatureMachine`
all keep their names, paths and method signatures (`read_preprocess`, `sign`, `complete`, `cache`,
`from_cache`). `FrostError` gained `InvalidSigningSet(&'static str)` and
`InvalidParticipantQuantity(usize, usize)` payload changes; check grease's match arms.

`ThresholdKeys::new(core)` is gone — `musig()` now returns `ThresholdKeys` directly.

### monero-oxide: crate and module map

| Was | Now |
| --- | --- |
| `monero_serai::transaction::Transaction` | `monero_oxide::transaction::Transaction` (now `Transaction<P: PotentiallyPruned = NotPruned>`; bare `Transaction` still means unpruned) |
| `monero_serai::block::Block` | `monero_oxide::block::Block` — `miner_transaction` is now **private** |
| `monero_serai::ringct::clsag::ClsagAddendum` | `monero_oxide::ringct::clsag::ClsagAddendum` (crate `monero-clsag`; definition and addendum bytes unchanged) |
| `monero_serai::generators::hash_to_point(bytes)` | **removed.** Use `monero_oxide::ed25519::Point::biased_hash(bytes)` — same Elligator-2 map, now constant-time, returns `Point` |
| `monero_wallet::rpc::FeeRate` | `monero_interface::FeeRate` |
| `monero_rpc::RpcError` | `monero_interface::InterfaceError`, plus `TransactionsError`, `FeeError`, `PublishTransactionError` — **one error type became four**; `WalletError` needs `#[from]` arms for each |
| `monero_simple_request_rpc::SimpleRequestRpc` | `SimpleRequestTransport::new(url) -> MoneroDaemon<SimpleRequestTransport>` — the stored connection type becomes `MoneroDaemon<SimpleRequestTransport>` |

### monero-oxide: the RPC trait split

`monero_rpc::Rpc` was replaced by a family of capability traits in `monero-interface`, all
re-exported via `monero_interface::prelude::*`: `ProvidesBlockchainMeta`, `ProvidesBlockchain`,
`ProvidesTransactions`, `ProvidesOutputs`, `ProvidesScannableBlocks`, `ProvidesDecoys`,
`ProvidesFeeRates`, `PublishTransaction`, plus `ExpandToScannableBlock`.

grease's four RPC methods map as:

| Was | Now | Note |
| --- | --- | --- |
| `rpc.get_height()` | `rpc.latest_block_number()` | **semantics changed** — `latest_block_number() == get_height() - 1`. Four call sites in `wallet/common.rs`, `wallet/multisig_wallet.rs` and `wallet/watch_only.rs` all need an off-by-one review; this is the most likely place for a silent scanning bug |
| `rpc.get_block_by_number(n)` | `rpc.block_by_number(n)` | |
| `rpc.get_scannable_block(b)` | `rpc.scannable_block(hash)` / `scannable_block_by_number(n)` / `ExpandToScannableBlock::expand_to_scannable_block(b)` | pick per call site |
| `rpc.publish_transaction(tx)` | same, via `PublishTransaction` | error type is now `PublishTransactionError` |

### monero-wallet 0.1 → 0.2

- `ViewPair::new(spend, view)` / `GuaranteedViewPair::new` — unchanged shape (both already returned
  `Result`), but `spend: Point` and `view: Zeroizing<ed25519::Scalar>` now use the new wrappers.
  `Scanner::new(pair)` and `scan(block)` are unchanged.
- `Change::new` / `guaranteed` / `fingerprintable` — signatures unchanged.
- `SignableTransaction::new` — signature unchanged, but `FeeRate` now comes from
  `monero-interface`. `SignableTransaction` lost its `PartialEq`/`Eq`/`Debug` derives in favour of
  a constant-time `PartialEq` and a redacting `Debug`.
- `SendError` — added `InvalidInputs` and `AmountsUnrepresentable { in_amount, out_amount }`;
  renamed `MaliciousSerialization` → `IncorrectSerialization`. All other variants unchanged.
- `OutputWithDecoys::new` — `DecoyRpc` → `ProvidesDecoys`, `ring_len: usize` → `u8`,
  `RpcError` → `TransactionsError`.

### The one genuinely structural break

`monero_wallet::send::multisig::TransactionPreprocess` and `TransactionSignatureShare` are now
**opaque newtypes**. In 0.1 they were `Vec<Preprocess<Ed25519, ClsagAddendum>>` and
`HashMap<Participant, Vec<SignatureShare<Ed25519>>>`, and `wallet/multisig_wallet.rs` reaches
directly into that structure — `.len()`, `.remove(..)`, per-input indexing — in at least eight
places (lines ~396-444 and ~498-512 at the current HEAD) in order to split a per-input preprocess
across the wire and to inject a test signing share.

This is the only part of the flag day that is a redesign rather than a rename, and it is what
carries the risk in K-26's estimate. The `deterministic_rng` + persisted-preprocess machinery sits
directly on top of it.

## 7. e2e lockfile coexistence: **no conflict**

Verified: with the new graph in `Cargo.toml` and `libgrease/Cargo.toml`, and `e2e/Cargo.toml`'s
three old-rev git pins (`monero-simple-request-rpc`, `monero-rpc`, `monero-address` at
`dc1b8dfc…`) left untouched, `cargo metadata` exits 0 and the lockfile carries 36 old-revision
entries alongside the new ones. Cargo is happy to hold both revisions of the same git repository.

`[patch.crates-io]` does not apply to git-sourced dependencies, so the old-rev crates are
unaffected by the patch closure.

**K-27 stays a separate ticket.** The e2e manifest edits do not need to be folded into the flag day.

**Resolution (K-27).** e2e's three pins were re-pointed at monero-oxide — `monero-rpc` became `monero-interface` +
`monero-daemon-rpc` — and every monero-oxide entry now lives in `[workspace.dependencies]`, so no member crate can
carry its own revision. The old revision is gone from every manifest and from the lockfile. e2e still does not
compile against the new `libgrease` API; only resolution was in scope.

## 8. MSRV / toolchain: **no pin needed**

`monero-wallet` 0.2, `monero-daemon-rpc` and `monero-simple-request-rpc` declare
`rust-version = "1.89"`; `dalek-ff-group` 0.5 declares 1.89; the rest of the serai crypto tree
declares 1.85. `rust-toolchain.toml` floats on `stable`, which is currently 1.97.1 — comfortably
ahead.

Recommendation: leave `rust-toolchain.toml` on `stable`, and optionally add
`rust-version = "1.89"` to `libgrease`'s `[package]` in K-27 so an old toolchain produces a clear
cargo error rather than a wall of syntax errors.

**Resolution (K-27).** `rust-toolchain.toml` left on `stable`; `rust-version = "1.89"` added to `libgrease`.

## 9. Fallback rule

Not triggered. The pure-crates.io July 2026 route (digest 0.10 generation) is **not** required and
is not recommended: the crates.io copies of `modular-frost` (0.11.1) and `multiexp` (0.5.1) are
*ahead* of serai `next`'s in-tree versions and would reintroduce exactly the split-family problem
the patch closure exists to solve.
