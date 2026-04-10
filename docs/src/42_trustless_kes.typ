// Preamble
#import "@preview/note-me:0.5.0": *
#import "metadata/nomenclature.typ": *
#import "metadata/front-matter.typ": algo

= Trust assumptions in the KES

@kesDesign mapped out the cryptography that the KES needs to manage. It did not cover how it might be implemented in a 
trust-minimizing manner. This section examines some practical approaches for implementing the KES as well as discussing some of the 
trade-offs involved.

A trustless (or trust-minimized) KES deployment must satisfy the following properties:

- *Collusion resistance.* The primary threat is the KES colluding with one party to share the counterparty's #w0 outside of the dispute
  protocol. This would allow the colluding party to unilaterally drain the channel.
- *Secrecy.* Neither channel party can access their counterparty's #w0 outside of the conditions defined by the protocol.
- *Conditional release.* #w0 is released if and only if the conditions in the dispute and claim phases are satisfied.
- *Verifiability.* All participants must be able to verify that the KES is operating correctly, and only according to the prescribed 
  protocols.
- *Censorship resistance.* in many respects, censorship is equivalent, or arguably, worse than collusion, since it can make it appear  
  that a party has become unresponsive, and the other two parties can carry out a completely valid-looking force-close. 

We can capture these requirements in these three properties:
1. We must be certain, and able to independently verify, that the code describing the KES algorithm, *and only that code* is executed as 
   part of the KES' duties.
2. We must be able to verify, within a suitable confidence threshold, that no coalition of less than the security
   threshold can recover #w0 (or anything from which #w0 can be derived) outside of the conditions in the dispute
   and claim phases. 
3. The KES must not be able to ignore valid messages from parties (censorship resistance).

Property 1 can be met to within a reasonable approximation by executing code on a decentralized public smart contract blockchain. The 
code does not have to be private. 
  
Property 2 is more challenging. For trustlessness, we need to convince ourselves that the KES as a whole is _unable_ to leak #kk to any 
other party within the constraints of a set of security assumptions. This is possible in a Trusted Execution Environment (<tees>), 
but at the time of writing, no smart contract system has a way of generating and then storing a verifiably random number in private 
storage (see <pvtState>).

Property 3 requires two ingredients that no centralized deployment can provide: (a) request submission and ordering
must be observable by parties other than the KES operator, so that censorship is _detectable_, and (b) the entity
that finalises which requests are processed must be a quorum rather than a single operator, so that censoring a
request requires corrupting an honest majority of that quorum rather than a single machine. BFT consensus on a
public blockchain delivers both: the mempool (or its equivalent) gives (a), and the validator set gives (b). Public
blockchains are therefore the natural vehicle for property 3; centralized solutions are excluded.

== The problem with private state on blockchains <pvtState>

There are several blockchain projects that purport private smart-contract support. Lead among them are Aleo and Aztec, both using 
ZK-SNARKs for private computation proofs. DarkFi is also in development, but is less mature. Tari supports confidential payments, and its 
architecture allows for private computation in future, but the current testnet design exposes all state to validators. 

For brevity and expedience, the remainder if this discsussion will assume Aztec as the chosen platform for the KES. Grease already makes 
use of Noir (Aztec's smart-contract language) and there are no features in the other projects that Aztec doesn't already have. Aztec is 
currently in "Alpha-mainnet" at the time of writing -- the rollup is live on Ethereum Mainnet with 500 validators, but the team considers
 the platform an alpha release with several #link("https://aztec.network/blog/critical-vulnerability-in-alpha-v4", "critical bugs").

In Aztec's model, private state is encrypted and owned by users who hold the corresponding decryption keys. Modifying private state requires
nullifying existing records and creating new ones (a UTXO model), which preserves privacy of state transitions. However, _someone always
holds the decryption key_ for any given piece of private state. In fact, there are no ZK blockchains at the time of writing that offer 
purely private storage. 

Until this is the case, we are forced down the path of multiparty computation. #kk needs to be sharded so that property 2 is satisfied. 
No-one knows the whole secret but say, $t$-of-$n$ parties can co-ordinate to sign messages. The Olaf protocol based on Frost3@frost3  
is one way of carrying this out, though there are others@frost@chilldkg@gennaro07.

=== A hybrid on-chain off-chain design

@kesAztecArch illustrates the architecture for a hybrid on-chain off-chain design. KES state storage and signature aggreagtion and 
verification is maintained on-chain in smart contracts. The KES private key #kk is sharded among $n$ signers that run "hot-wallet" style 
daemons to respond to signature requests. A threshold $t$ is chosen such that any $t$ signers can co-operate to sign a message with #kk.
 No single signer knows that key, and $t$ must be large enough such that the probability of collusion is suitably low.   

*FrostCoordContract*: 
- Public functions on Aztec L2. 
- Stores the signer registry and aggregate public key $P_K$. 
- Verifies FROST signatures. 
- Does not orchestrate DKG or signing rounds -- those happen off-chain between committee members. 
- The contract is a registry and verification endpoint.

*KesStateContract*: 
- Public functions managing channel state. 
- Stores `OpenChannel` and `PendingChannelClose` records in public storage. 
- Enforces the dispute state machine using L1-derived timestamps. 
- Issues release authorizations.

*Signer daemons*: ($n$ instances) 
- Off-chain processes. 
- Each holds a shard of #kk in local memory. 
- Watches the L2 public state for events. 
- Participates in peer-to-peer DKG, threshold decryption, and FROST signing rounds. Submits results to the L2
  contract via standard transactions.

#figure(
[```
+--------------------+                     +-----------------------+
|  KesStateContract  |                     |   FrostCoordContract  |
| - OpenChannel      |                     | - signer registry     |
| - PendingClose     |                     | - P_K storage         |
| - dispute logic    |                     | - sig verify          |
| - release auth     |                     |                       |
+--------------------+                     +-----------------------+
         ^                                             ^
         |                                             |
         |                                             |
         |                                             |
         +---------------------+-----------------------+
                               |
ON-CHAIN AZTEC NETWORK         |
===============================================================
OFF-CHAIN & P2P                |
                   +-----------+---------...--------+
                   v           v                    v  
          +----------+    +----------+          +----------+
          | Signer 1 |    | Signer 2 |   ...    | Signer n |
          | k_{K_1}  |<-->| k_{K_2}  |<--...--->| k_{K_n}  |
          | (daemon) |    | (daemon) |          | (daemon) |
          +----------+    +----------+          +----------+
```],
caption: [KES hybrid-architecture sketch for Aztec],
kind: image
) <kesAztecArch>

This design satisfies all three properties above, at the cost of much higher complexity. Liveness is likely to be on the order of 
1-2 minutes for channel initialization, which while fairly slow, is still acceptable, since the channel won't truly be open until the 
monero funding transactions have been included in a block. 

The choice of $t$ is a direct trade-off: smaller $t$ improves liveness but increases the chance of collusion. A reasonable starting point is
$t approx 2n/3$, matching the BFT threshold of the underlying L2.

FROST gives the signing committee a way to produce Schnorr signatures under #Pk without ever reconstructing #kk.
It does not cover recovering #w0 from the encrypted offset $chi$ that the parties submit. `DecryptMessage` (@decM) requires the holder 
of #kk to compute $#kk dot.c R$, which is a Diffie-Hellman operation, not a Schnorr signature. The hybrid design therefore provides a 
second threshold primitive in addition to FROST: threshold decryption of the hashed-ElGamal ciphertexts produced by `EncryptMessage` 
(@encM).

Fortunately, the encryption scheme in @encM is friendly to this. Threshold decryption is possible using the same shares that parties 
obtained during the Olaf DKG ceremony.

@channelKeys defines a per-channel keypair $#kg = #chs dot.c #kk$ with $#Pg = #kg dot.c G$, and the
proof-of-knowledge signatures returned during channel opening are signed under #kg, not #kk. The hybrid design
inherits this without needing a fresh DKG per channel because Shamir secret sharing is linear over the scalar
field, the share

$ kg_i = #chs dot.c kk_i $

is a valid Shamir share of #kg with the same threshold $t$ and the same evaluation points as the original
sharing of #kk. 

@channelKeys requires the KES to discard #chs immediately after deriving #kg. In the hybrid design this
requirement is relaxed. Under the standing assumption that fewer than $t$ signers collude, no-one learns #chs so there is nothing to 
discard.

The added complexity, and by extension, cost, means that KES signers will probably need to be compensated for running daemons. As
mentioned in @slashing, adding a fee component to the KES is relatively straightforward, but is out of scope for this white paper.

=== Additional applications and distribution of risk

One may observe that the design in @kesAztecArch could easily be generalized to store _any_ encrypted data in a decentralised, 
censorship-resistant manner. To whit, the design migrates from a _Key_ escrow service to a _Document_ escrow service.

If one were to build this out, the `KesStateContract` is but one of many types of data the "DES" signers are prepared to encrypt. We will 
not dive down this rabbit hole here, but this is worth exploring further if one concludes that this design needs a funding mechanism to 
be sustainable, but that Grease alone may or may not provide sufficient volume to support the KES  on its own.

Possible applications include:
- On-chain insurance contracts,
- Decryption of documents under certain conditions, e.g. crypto inheritance strategies with dead-man switches,
- On-chain wagers and prediction markets


== Using TEEs <tees>

TEEs satisfy Properties 1 and 2 to a reasonable degree (see the caveats below). However, one cannot run a KES on a single TEE since a 
malicious KES operator could simply censor messages from say, Alice, which would allow Bob to submit a force-close request and extract 
Alice's #w0 after the time-out without the KES operator even needing to break the enclave boundary!

Therefore, in order to satisfy property 3, you need distributed TEE infrastructure with the ability to form BFT consensus across the 
network. As luck would have it, such a system already exists -- the Secret Network@secrt. By leveraging the infrastructure and consensus 
machinery already deployed in Secret, deploying a KES in a distrubuted TEE network becomes fairly straightforward.

=== The KES on the Secret network

Deployment to the Secret Network looks almost identical to a centralized KES contract (@KesSecrtArch) -- the network is purely used to 
provide censorship
 resistance.

#figure(
[```
+-----------------------------+
|         KesContract         |
|                             |
|  Private state (TEE-enc):   |
|   k_K                       |   <-- generated once, inside enclave,
|                             |       never materialised outside
|  Public state:              |
|   P_K = k_K . G             |
|   OpenChannel records       |
|   PendingClose records      |
|   code_id (content hash)    |
|                             |
|  Execute:                   |
|   init()          (once)    |
|   open_channel(...)         |
|   force_close(...)          |
|   release(...)              |
|   sign_pok(...)             |
|                             |
|  Query:                     |
|   p_k()                     |
|   channel_status(id)        |
+-----------------------------+
```],
kind: image,
caption: [KES contract oultine for the Secret Network]
) <KesSecrtArch>

Every node must create the same private key in order to come to consensus. The Secret network actually provides a secret random number to 
enclaves for each block, so the key can be derived without any external observer knowing what it is, for example

```rust
// Derive k_K from consensus-seeded randomness.
    let seed = ctx.env.block.random.ok_or(Error::NoRandomness)?;
    let mut okm = [0u8; 64];
    Hkdf::<Sha512>::new(Some(b"kes.contract.master_key.v1"), seed.as_slice())
        .expand(b"k_K", &mut okm)
        .unwrap();
    let k_k = Scalar::from_bytes_mod_order_wide(&okm);
    let p_k = &k_k * BASEPOINT;
```

==== Advantages

- Simple deployment -- almost identical to a centralized KES.
- Performance is very good. Tendermint BFT means finality in one block. Block intervals are 5-6s.
- Permissionless operation
- Liveness and availability guarantees are identical to that of the the Secret network.
- Secret contracts are pure Rust compiled into WASM. Thus Curve25519 can be used for $EE_K$, making the DLEQ proofs trivial.
- No human ever sees the private key. 
      
==== Disadvantages

- *TEE single point of trust.* Until Secret diversifies its hardware requirements, if SGX is compromised network-wide, all key shares 
  for all signer contracts are exposed simultaneously. 
- *Limited decentralisation.* 80 validators, all running the same Intel SGX hardware. Although, for censorship resistance, this is 
  likely sufficient.

==== Intel SGX exploits

The locus of trust for a Secret-based KES shifts to the TEE hardware.

Currently Secret requires the use of Intel's SGX trusted enclaves, although they are starting to support other 
hardware@secretvm-amd-sev-snp including AMD SEV-SNP. 

Unfortunately, SGX has a fairly long history of vulnerabilties.

Pre-2024, when Secret was fully permissionless (for validators), the Foreshadow (2018), SGAxe (2020)  and Downfall exploits may have led 
to the private key leaking had the KES been running. Post-2024, Secret validators go through a vetting process of sorts. Even though 
this gating is friction for decentralization, it has improved the security of the Secret network. Several exploits that involved faking 
attestation certificates, including _wiretap.fail_, would have been caught by the Secret governance process. 

Overall, for Grease, the conclusion is that while Secret's security is improving, SGX is still its Achilles' heel. That said, given how 
simple the deployment is, it's the author's opinion that a Secret-based KES would be fine for low- to medium value channels as a 
stop-gap while a more robust KES is built out, rather than having no KES at all, or only trusted contralized KESs (recall that Grease 
supports multiple KESs-- selecting the KES is part of the channel opening negotiation).
   
== A note on economic incentives for centralized KEServices. <slashing>

We also considered centralized KES systems that are _incentivized_ to behave correctly. 

The idea is that the KES charges a small fee for escrowing the #w0 values. In turn, the KES stakes their reputation, or even monetary 
tokens on being honest.
 
Fees are a straightforward extension to Grease:
- There are already multiple rounds of communication between Customer, Merchant and KES during channel establishment. A KES fee could be 
grafted into the existing messages.
- The merchant is already responsible for communicating with the KES. He would be responsible for paying the fee, and recovering it by 
including it into the channel payments. If the KES' currency is not Monero, the merchant can manage this as well by aggregating conversion
 over multiple channel openings.

Let's assume that fraud proofs are relatively easy to produce in Grease, since both parties to the channel keep signed records of every 
channel update. If a channel was closed with an outdated state, the aggrieved party should be able to demonstrate this convincingly. 

However, there is a problem: Alice and Bob can collude _against the KES_:

- Alice gives $w0^A$ to Bob directly (off-protocol, without KES involvement).
- Bob closes the channel on Monero.
- Alice files a fraud proof, claiming the KES colluded.
- The KES stake is slashed / or the KES' reputation is destroyed.

There is no straightforward design that mitigates this attack. For example, requiring Alice and Bob to escrow additional funds that could
 be slashed by a counterproof breaks the very point of Grease in the first place: Simple, low-friction payment channels.

If preventing collusion against the KES is not practical, then no fraud-proof-based system is viable, which essentially excludes 
centralized KES implementations from all but very low-stakes applications (e.g. conferences, or festivals, where the channels are 
naturally short-lived and carry only a few tens of dollars at most).

  
== Summary

Centralized KES deployments are simplest and fastest, but they require parties to trust that the KES won't collude with their counterparty
 to steal funds. This is fine for testing and low-stakes applications, but is not sufficient for Grease's broader adoption goals.

The Secret Network provides a BFT network of Trusted Execution Environments (TEE) that --on the face of it-- deliver exactly what the 
  KES needs: private secret storage, verifiable computation and censorship resistance. Unfortunately the "T" in TEE is not particularly 
  well-earned. Nevertheless, the Secret network is a decent interim solution for the KES, providing a bridge between a purely centralized 
  KES and a longer-term SNARK-based solution.

A blockchain-only trustless KES deployment is not possible with current ZK-SNARK based platforms, since they cannot store and use private 
  state. Aztec, as arguably the leading ZK blockchain, has private execution on _client devices_. The KES secret can't be placed in the 
  hands of any single entity, since that invites collusion. Therefore a hybrid model is posited: KES co-ordination and storage on-chain 
  coupled with an Olaf/FROST3 distributed signing committee. Individual signers operate as an always-on network service.

The proposed approach forward for Grease would be the following:

1. Start with a centralized KES for the beta phase. This allows the UX of the channel parties to be ironed out and the core cryptography
   of the escrow service to be battle-tested.
2. Deploy the first production KES on the Secret network. We don't particularly like Intel SGX, but it's a relatively cheap deployment, 
   is better than a purely centralized KES, and bridges the gap until,
3. A hybrid escrow service on Aztec is complete; or if private storage is solved, simply migrate off of TEEs to a SNARK-based platform. 
   In both cases, there may be a market for providing a more generalized "Document Escrow Service", though determining the level of 
   demand for such a service is outside the scope of this document.       

