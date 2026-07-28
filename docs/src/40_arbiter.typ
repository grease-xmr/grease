// Preamble
#import "@preview/note-me:0.5.0": *
#import "metadata/nomenclature.typ": *
#import "metadata/front-matter.typ": algo

= The Arbiter <arbiterDesign>

== What the arbiter is for

A Grease channel keeps its funds in a 2-of-2 multisig output that neither party can spend alone, and every channel state is a fully
pre-signed transaction that closes the channel at that state's balances — deliberately left incomplete by a secret offset so that it cannot
be broadcast until the offset is supplied. Because neither party can broadcast a commitment on its own, there is no race to rush a stale
state onto the chain. Two situations remain that the channel cannot resolve for itself, and resolving them is the arbiter's entire job:

/ Liveness release: the counterparty disappears. The honest party wants to close at the latest agreed state but cannot, because it is
  missing the offset that completes the counterparty's half of the closing signature. Something must release that offset on request.

/ Cheat adjudication: a party claims that some _old_ state is the latest, hoping to close at balances that favor it. Something must
  recognize that a newer state exists and make sure only the newer state can ever be closed.

Both reduce to one task the Monero base layer cannot perform: decide, given two cross-signed records, _which is newer_, and release exactly
the offset that closes at it. The arbiter performs it. The rest of this chapter is about giving the arbiter that authority *while letting it hold
no secret whose leak could cost a channel its funds*. It never holds a share of the funding key, never learns a channel's balances, and
stores no per-channel secret. It is a small, deterministic state machine whose only power is to attest a public statement — and that
attestation is exactly what unseals the correct offset.

#note[
  The arbiter is never touched on the common paths. Channel updates are peer-to-peer, and a cooperative close is a single ordinary Monero
  transaction (@coopClose). The arbiter is consulted only when a party goes silent or tries to cheat.
]

== Custody versus authority

It helps to separate two things a third party might do, because keeping them apart is the whole idea.

/ Custody: holding a secret whose leak is catastrophic. If a third party holds a value that can complete a closing signature for a
  favorable state, then whoever obtains that value can drain the channel. A design built on custody is only ever as safe as the promise
  that the secret never leaks — and on a public, auditable platform that promise is very hard to keep.

/ Authority: deciding, in public, which public statement to certify. Choosing "state $n$ is the latest" from the records the parties have
  already exchanged leaks nothing. It is a pure function of information both parties already hold.

A public smart-contract chain is excellent at authority and structurally poor at custody. It can _run code_ verifiably: place the logic
on-chain and consensus guarantees that this logic, and only this logic, executed. What it cannot do is _store a secret that its own
validators cannot see_. On a transparent chain all state is public. On a zero-knowledge chain, "private" state is encrypted to some party
who holds the decryption key — so the secret still exists somewhere, and its leak is exactly the failure a custody-based design exists to
prevent.

The arbiter sidesteps this by storing *no per-channel secret at all*. What it needs from its platform is only two things:

+ *verifiable deterministic execution* — the published state machine, and nothing else, runs; and
+ *a threshold key held by the validator set itself* — used not to store channel secrets, but to *sign a statement on demand*, where the
  signature on a statement is exactly the key that unseals that statement's offset.

The second ingredient is what makes this practical, and it is available today as a production service (@icp). A validator set can jointly
hold a single threshold-BLS master key — no member knows it in full, and a Byzantine quorum can sign with it — exposing one operation: given
an application-chosen byte string $m$, and given that the on-chain logic authorizes it, release the group's BLS signature on $m$. That
signature is the arbiter's attestation of $m$; as @attestation shows, it is also an identity-based decryption key for $m$. The master key is
_global_ and _application-agnostic_: it is not created per channel, holds no channel's funds, and is shared across every application on the
platform. Its compromise is therefore not a quiet, per-channel theft but a platform-wide, publicly evident event — the same risk profile as
a compromised public randomness beacon.

So the arbiter keeps *authority* — which statement is true, decided by public code — and sheds *custody* — any secret whose leak matters.
The residual trust is not "a custodian will not leak my key"; it is "a public validator set runs its published logic and does not collude
beyond its fault threshold". That is close to the trust the platform already demands of every application it hosts, with one
qualification: the arbiter concentrates it. Its funds rest on the unforgeability and confidentiality of _one_ validator subnet's threshold
key, and on governance over that subnet, rather than on an ecosystem-wide average — so the incentive to corrupt exactly that subnet is
higher than for an application that only stores public state.

== Attestation as a decryption key <attestation>

The mechanism that turns an attestation into a release is identity-based encryption built from a threshold-BLS committee. Let the arbiter
committee hold a threshold-BLS key over a pairing-friendly curve with additive groups $GG_1$, $GG_2$, target group $GG_T$, generators $G_1$,
$G_2$, and a pairing $e: GG_1 times GG_2 -> GG_T$. The committee's master secret is a scalar $z$ that no member knows in full; the master
public key
$ Z = z dot.c G_2 $
is published once and is stable for the committee's lifetime. Let #H2P([...]) hash a byte string to a point in $GG_1$ and #H2F([...]) hash a
$GG_T$ element to a scalar in $ZZ_ell$, where $ell$ is the prime order of the Ed25519 group on which offsets live. The pairing groups
$GG_1, GG_2, GG_T$ share a prime order $q$, and we fix the mask modulus $N = ell$ throughout — @bindingProof shows why identifying the two,
rather than reducing offsets modulo $q$, is what makes the binding proof cheap.

For any statement $m$, the committee's BLS signature on $m$ is
$ sigma_m = z dot.c hash(P, m) in GG_1. $
Producing $sigma_m$ needs a quorum; verifying it is the pairing check $e(sigma_m, G_2) = e(hash(P, m), Z)$. The key observation is that this
same $sigma_m$ is an _identity-based decryption key_ for the identity $m$. A party can encrypt a scalar offset $omega$ against the statement
$m$ using the arbiter's _stable_ public key $Z$, long before anyone has signed $m$:

#algo(
  caption: [Encrypt an offset to a statement.],
  title: [`EncryptToStatement`. $Z$ is the arbiter's master public key; $m$ is the statement; $omega$ the offset.],
  [
    + $(U, c) = "EncryptToStatement"(omega, m, Z)$
    + Select a random scalar $r$, $0 < r < q$ (the pairing order, *not* the mask modulus $N$).
    + Calculate:
      + $U = r dot.c G_2$
      + $y = e(hash(P, m), Z)^r$ in $GG_T$
      + $s = H2F(y)$
      + $c = (omega + s) mod N$
    + Return $(U, c)$.
  ],
)<encStmt>

#algo(
  caption: [Decrypt an offset once the statement has been attested.],
  title: [`DecryptWithAttestation`. $sigma_m$ is the arbiter's attestation of $m$.],
  [
    + $omega = "DecryptWithAttestation"(U, c, sigma_m)$
    + Calculate:
      + $y = e(sigma_m, U)$ in $GG_T$
      + $s = H2F(y)$
      + $omega = (c - s) mod N$
    + Return $omega$.
  ],
)<decStmt>

Correctness follows from bilinearity: once the committee releases $sigma_m = z dot.c hash(P, m)$,
$ e(sigma_m, U) = e(z dot.c hash(P, m), space r dot.c G_2) = e(hash(P, m), G_2)^(z r) = e(hash(P, m), Z)^r = y, $
so the decryptor recovers the same mask $y$ and hence $omega$. The ciphertext can be formed by anyone at any time against the stable $Z$;
decryption becomes possible *exactly when* the committee attests $m$, and not before.

The property the whole design rests on is a corollary: *whoever decides which $m$ gets attested decides which ciphertexts can ever open.* If
the arbiter attests $m$ only when its deterministic logic says $m$ is true, then ciphertexts addressed to false statements stay sealed
forever — with no custodian, no per-message secret, and no way for any single committee member to release anything alone.

== Gating a close on the true latest state

Recall that each channel state's unilateral close is gated by a secret offset: to complete the counterparty's half of the closing signature
for state $i$, a party needs that party's offset $wn(i)$, whose public point is $Q_i = wn(i) dot.c G$ on Ed25519.#footnote[Under FCMP++ the
  spend proof checks a signature against two bases at once, so the offset is applied to both the standard generator and the re-randomized
  key-image base; the encrypted value is the same scalar $wn(i)$, and the account here is unchanged.] We bind that offset to a statement.

At each update to state $i$, the parties agree the statement
$ m_i = (#raw("id"), i) quad ("on channel" #raw("id") ", state" i "is the latest"), $
where `id` is the channel identifier (@channelId), which commits to the funding output. Each party generates a _fresh_ offset $wn(i)$ for
the counterparty's state-$i$ close, and hands the counterparty an `EncryptToStatement` ciphertext of that offset addressed to $m_i$ — a
*verifiably encrypted offset*. Because it is worthless unless it is honest, it travels with a non-interactive proof — constructed in @bindingProof — establishing, as a single
statement, that

+ $(U, c)$ is a well-formed ciphertext under the arbiter's stable key $Z$, addressed to *exactly* $m_i$; and
+ the offset sealed inside decrypts to the discrete logarithm of the *very adaptor point $Q_i$* used in the counterparty's held
  pre-signature for state $i$.

The receiving party verifies this proof before it treats the update as complete. Offsets are freshly generated and domain-separated per
(channel, state, party); reusing one would let a single attestation unseal ciphertexts across many channels at once.

#note[
  The arbiter never sees a verifiably encrypted offset. Ciphertexts live only with the two parties. The arbiter's release is the public value $sigma_m$, and
  whoever holds the matching ciphertext can then decrypt it — exactly as anyone can decrypt a message timelocked to a randomness beacon once
  that beacon publishes the round.
]

Putting the pieces together explains why cheating cannot pay. To complete a close at state $i$ a party needs $wn(i)$, sealed under $m_i$,
unsealable only if the arbiter attests $m_i$; and the arbiter (@stateMachine) attests only the statement at the channel's high-water mark.
Therefore:

- an *honest* close at the latest state $n$ opens, because the arbiter attests $m_n$;
- a *stale* close at state $i < n$ never opens, because $m_i$ is never attested once a newer record has been presented — its ciphertext stays
  sealed;
- a *fabricated* state has no verifiably encrypted offset and no cross-signed record, so there is nothing to attest and nothing to open.

The cheat is not punished; it is *frozen*. No revocation secret, no penalty transaction, and no collateral are needed for the adjudication
to be safe.

== The binding proof <bindingProof>

The two requirements just stated — that $(U, c)$ is well-formed under $Z$ and addressed to exactly $m_i$, and that the sealed offset is the
discrete logarithm of the adaptor point $Q_i$ the recipient already holds — are met by one non-interactive proof, produced by the encryptor
and checked before the update is treated as complete. It carries a hard confidentiality constraint: it must reveal *nothing* about the offset
$omega = wn(i)$. The encryptor generated $omega$ for the counterparty's own state-$i$ close and adaptor-signed that close with it, so an
$omega$ learned at update time would let the recipient complete that close at once — including one state later, when it is stale. The proof is
therefore zero-knowledge in $omega$.

With the mask modulus fixed at $N = ell$ (@attestation), $omega$ is a native Ed25519 scalar and the recipient computes, for free,
$ S := c dot.c G - Q_i = (omega + s) dot.c G - omega dot.c G = s dot.c G, $
since $G$ has order $ell$ and reducing modulo $ell$ leaves no carry in the exponent. So $s dot.c G$ is pinnable — yet $s = H2F(y)$ is a
random-oracle hash of the pairing output, and no Σ-protocol can cross that hash to tie $s dot.c G$ back to $U = r dot.c G_2$. Every efficient
"the plaintext is this discrete logarithm" proof relies on the ciphertext being an _algebraic_ function of the plaintext, and the hash mask
destroys that structure; proving the hash relation directly would force a pairing and a hash into a SNARK circuit over BLS12-381, the curve
ICP's vetKD fixes and the one with no cheap 2-chain. We avoid it: instead of proving the relation, we open a random, below-threshold subset of
an honest secret sharing, where on the opened shares the hash is simply recomputed in the clear.

It helps to be exact about what $N = ell$ buys, since it is easy to overstate. It is _not_ recoverability — $omega mod ell$ is a usable
Ed25519 scalar under any modulus. It is (i) that $S = s dot.c G$ is an _exact_ identity: under $N = q$ it would read
$S = s dot.c G - k dot.c (q mod ell) dot.c G$ for an unknown carry $k in {0, 1}$, which breaks the free equation and leaks a biased function of
$omega$ across ciphertexts; and (ii) that $c |-> omega$ given $s$ is a bijection, which the share-consistency check below needs in order to pin
each share to a single value.

The proof is a publicly verifiable secret sharing of $omega$: a Feldman#footnote[The both-bases sharing and the cut-and-choose follow the
timed-release line of VTS (Thyagarajan et al., CCS 2020) and PayMo (`assets/2020-1441.pdf`).] sharing on _both_ FCMP++ bases, each share
encrypted to the same statement, made honest by a Fiat–Shamir cut-and-choose. Write $G$ and $B$ for the two bases the spend proof checks the
offset against#footnote[$B$ is the re-randomized key-image generator, not a nothing-up-my-sleeve point. Which base is fixed — the key-image
generator $I$ itself or a per-broadcast re-randomization — and how the offset composes with the FCMP++ SA+L spend proof is an open design item;
the proof binds whichever $B$ is fixed at update time by committing $F_j^B$ against it.], and $Q_i = omega dot.c G$, $Q_i^B = omega dot.c B$ for
the offset's two adaptor points.

#algo(
  caption: [Produce a verifiably encrypted offset with its binding proof.],
  title: [`ProveEncryptedOffset`. Inputs $omega, m, Z, Q_i, Q_i^B$; parameters $(n, t)$.],
  [
    + Derive every random choice below from a PRF keyed on $(omega, m, Z)$, so re-running the prover reproduces the *same* proof
      byte-for-byte; a second proof over the same $omega$ that opened a _different_ subset would leak it.
    + Choose a degree-$(t-1)$ polynomial $f(x) = sum_(j=0)^(t-1) a_j x^j$ over $ZZ_ell$ with $a_0 = omega$; the shares are $omega_k = f(k)$,
      $k = 1, ..., n$.
    + Publish Feldman commitments to the coefficients on both bases, $F_j = a_j dot.c G$ and $F_j^B = a_j dot.c B$ for $j = 0, ..., t-1$. By
      construction $F_0 = Q_i$ and $F_0^B = Q_i^B$, and each share point $sum_j k^j F_j$ is then determined.
    + For each coefficient attach a Chaum–Pedersen $"DLEQ"_(G,B)(F_j, F_j^B)$, proving $F_j$ and $F_j^B$ carry the same exponent $a_j$.
    + For each share form $(U_k, c_k) = "EncryptToStatement"(omega_k, m, Z)$, sampling a fresh $r_k$ uniformly in $ZZ_q^*$. This is the only
      pairing work, done in the clear.
    + Compute the cut-and-choose challenge $I = H_"FS"(#raw("dst"), m, Z, B, Q_i, Q_i^B, {F_j}, {F_j^B}, {U_k}, {c_k}, n, t)$ as a
      $(t-1)$-element subset of ${1, ..., n}$, and open it: reveal $(r_k, omega_k)$ for each $k in I$.
    + Emit all $n$ share-ciphertexts ${(U_k, c_k)}$, the commitments ${F_j}, {F_j^B}$ with their DLEQs, the subset $I$, and the openings
      ${(r_k, omega_k)}_(k in I)$. The $n - (t-1)$ unopened ciphertexts are the verifiably encrypted offset.
  ],
)<proveOffset>

#algo(
  caption: [Verify a binding proof.],
  title: [`VerifyEncryptedOffset`],
  [
    + *Target binding.* Check $F_0 = Q_i$ and $F_0^B = Q_i^B$; this ties the sharing to the exact adaptor points *unconditionally*.
    + *Both bases.* Check every $"DLEQ"_(G,B)(F_j, F_j^B)$.
    + *Challenge.* Recompute $I$ from the transcript and confirm it matches the opened set.
    + *Opened shares.* For each $k in I$ recompute $U_k = r_k dot.c G_2$, $y_k = e(hash(P, m), Z)^(r_k)$, $s_k = H2F(y_k)$, and verify
      $c_k = (omega_k + s_k) mod ell$, $omega_k dot.c G = sum_j k^j F_j$, and $omega_k dot.c B = sum_j k^j F_j^B$.
    + *Point hygiene.* Reject unless every received Ed25519 point ($Q_i, Q_i^B$, all $F_j, F_j^B$) is non-identity and torsion-free
      ($ell dot.c P = 0$); recompute $B$ locally rather than trust it on the wire; require canonical scalars (reject any $c_k$ that is not the
      least residue modulo $ell$); subgroup-check every $U_k in GG_2$, the unopened ones included; and reject any repeated $U_k$.
    + Accept iff every check passes.
  ],
)<verifyOffset>

On the dispute path recovery is cheap and robust. The recipient already holds the $t-1$ opened shares in the clear — they are part of the
proof — so once the arbiter releases $sigma_m$ it decrypts unopened ciphertexts, $omega_k = (c_k - H2F(e(sigma_m, U_k))) mod ell$, until _one_
passes $omega_k dot.c G = sum_j k^j F_j$; that is the $t$-th consistent point. It Lagrange-interpolates $omega = f(0)$ and confirms
$omega dot.c G = Q_i$. Because the opened shares and the target $Q_i$ are already verified, a single good unopened ciphertext suffices, and no
erasure-coding layer is needed.

#note[
  *What the proof rests on.* Target binding ($F_0 = Q_i$) is unconditional. Hiding is information-theoretic in the sharing — the $t - 1$
  opened shares lie below the reconstruction threshold and are independent of $omega$, and Feldman reveals only $a_j dot.c G$, already implied
  by $Q_i$ — and otherwise rests on the discrete-log hardness the adaptor point $Q_i = omega dot.c G$ assumes anyway. Soundness is
  _statistical_: a dishonest bundle passes only if the cut-and-choose opens exactly the consistent $(t-1)$-subset while every unopened share is
  inconsistent — probability $1 \/ binom(n, t-1)$, or $q_H \/ binom(n, t-1)$ against a prover that grinds the Fiat–Shamir challenge. The payoff
  of a surviving cheat is a _frozen_ update, one whose offset cannot be decrypted at dispute time, never the completion of a _wrong_ offset.
  The assumptions are exactly those the arbiter already carries — BF-IBE / BDH in the random-oracle model — plus Fiat–Shamir: no trusted setup,
  no SNARK, no cross-group DLEQ, and @encStmt is reused verbatim.#footnote[A one-page game-based reduction, and the party-side vetKD
  reproduction vectors of @icp, are tracked as follow-ups before deployment.]
]

Three details close the construction.

- *Soundness budget.* Take $(n, t) = (104, 53)$, so the opened subset has $t - 1 = 52$ shares and $binom(104, 52) approx 2^100$. The margin is
  deliberately generous: because a surviving cheat only _freezes_ one update rather than stealing, that much work to force a single dispute to
  fail is beyond any rational attacker. A channel wanting smaller messages can lower $n$; one wanting more margin can raise it.
- *The artifact is per-update.* The offset and its proof travel on _every_ update, not only on the dispute path, so the $approx 20$ KB at these
  parameters is a standing per-update cost, not a rare one. If it ever dominates, the constant-size McFly-style algebraic variant is the
  documented upgrade, at the price of a re-architected ciphertext and chunked decryption.
- *#raw("H2F") concretely.* Instantiate $H2F$ as a wide reduction — read $64$ uniform bytes (SHA-512, or RFC 9380 `expand_message` with
  $L = 48$) as an integer modulo $ell$ — of a Grease-unique domain-separation tag prepended to the canonical fixed-length $GG_T$ serialization
  of $y$. The wide reduction holds $s$ within $2^(-128)$ of uniform on $ZZ_ell$, so $c = omega + s$ is a sound one-time pad; the unique tag
  separates this hash from vetKD's own hashes of pairing outputs; and both parties must reproduce the same $GG_T$ serialization (@icp), since a
  divergence there stays invisible until decryption fails on the dispute path.

== The dispute state machine <stateMachine>

The arbiter keeps a small amount of *non-secret* state per channel: a monotonically increasing *high-water mark*, an *adjudication window*
anchored to a consensus clock, a *resolved tombstone*, and a public append-only *action log*. When a party presents a cross-signed record,
the arbiter runs the lifecycle shown in @arbiter_lifecycle.

The record a party presents is the same object the parties sign on _every_ update:

```rs
pub struct UpdateRecord {
  /// The globally unique channel id (commits to the funding output)
  channel_id: ChannelId,
  /// The monotonic update count for this state
  update_count: u64,
  /// The canonical signable hash of state i's closing transaction
  close_hash: Hash,
  /// This record signed by the customer, P_A
  signature_a: SchnorrSignature,
  /// This record signed by the merchant, P_B
  signature_b: SchnorrSignature,
}
```

Verifying an `UpdateRecord` is two Schnorr checks and a well-formedness check on the record itself — a valid `channel_id`, an update count,
and a present `close_hash`. That both parties signed the record is what vouches that `close_hash` is the legitimate closing transaction for
this state; the arbiter does not open the id or reconstruct the transaction, so it never learns the funding output, the linking tag, or the
balances. It sees only an opaque id and an update count.

#figure(
  ```mermaid
  activityDiagram
    start
    :A party presents its cross-signed record for state i;
    if (record valid and channel not resolved?) then (no)
      :Reject the request;
      stop
    else (yes)
    endif
    if (i above the high-water mark?) then (yes)
      :Advance the high-water mark to i;
      :Open or refresh the adjudication window;
    else (no)
      :Ignore the stale record;
    endif
    :Wait for the window to elapse;
    :Attest the statement at the high-water mark and release its key;
    :Append to the public log and set the resolved tombstone;
    stop
  ```,
  caption: [The arbiter's per-channel lifecycle. The high-water mark only ever rises, so the statement finally attested is the maximum
    record anyone presented.],
  kind: image,
) <arbiter_lifecycle>

#algo(
  caption: [The arbiter's response to a presented record.],
  title: [`onPresentRecord(rec: UpdateRecord)`],
  [
    + Validate `signature_a` and `signature_b` over the record, and that `rec` is well-formed (a valid `channel_id`, an update count, and a
      present `close_hash`). If not, *return* Fail(`Invalid`).
    + Fetch the `DisputeState` for `rec.channel_id`; create one if absent.
    + *if* `state.resolved`: *return* Fail(`AlreadyResolved`).
    + *if* `rec.update_count > state.high_water`:
      + `state.high_water = rec.update_count`
      + `state.window_expiry = now() + dw` (anchored to the platform's consensus time or a beacon round)
      + append `(RecordPresented, rec.update_count)` to `state.log`
    + *else*: append `(StaleRecordIgnored, rec.update_count)`; take no further action.
    + Return Ok.
  ],
)<onPresent>

When the window elapses with no higher record, the arbiter attests the high-water statement and logs it:

#algo(
  caption: [Resolving a dispute at the window's close.],
  title: [`onWindowElapsed(id: ChannelId)` — self-triggered by an on-chain timer],
  [
    + Fetch the `DisputeState` for `id`; *if* `state.resolved`, *return*.
    + *if* `now() < state.window_expiry`, *return* (not yet).
    + Let $overline(i) =$ `state.high_water` and $m = (#raw("id"), overline(i))$.
    + Compute the attestation $sigma_m = z dot.c hash(P, m)$ under the threshold key and publish it.
    + Append `(Attested, high_water)` to `state.log`; set `state.resolved = true`.
  ],
)<onElapsed>

Two rules keep the attestation honest and useful. First, *the window anchors to the platform's consensus clock or a beacon round, never to a
host's wall-clock* — a single operator that controlled a clock could otherwise freeze the window or fast-forward through it, whereas
consensus time cannot be moved by a minority below the fault threshold. Second, *the attestation binds the specific close it authorizes*,
and it does so without the arbiter inspecting the transaction: $m_i$ names `id`, which commits to the funding output (@channelId), and the
offset it unseals is bound at update time to the adaptor point of _this_ state's closing signature (its binding proof). So even
though the released $sigma_(m_i)$ is public, it completes nothing but the one close it names — a stale or foreign transaction has no
matching offset to complete.

== The dispute in practice <disputeFlow>

*Honest unilateral close.* The counterparty has gone silent. The honest party presents the record for the latest state $n$; the arbiter sets
the high-water mark to $n$ and opens the window; no higher record arrives; at the window's close the arbiter attests $m_n$. The honest party
decrypts the counterparty's offset $wn(n)$ (@decStmt), completes the counterparty's half of the closing signature, and broadcasts the
state-$n$ close. The window is the dispute delay — measured in hours, configurable per channel — and the counterparty's balance is paid to
its own address regardless.

*Cheating is frozen.* Suppose a party instead presents a stale record for state $i$, hoping to close at a more favorable old balance. The
arbiter opens the window at high-water $i$. The honest party — watching the arbiter's log, or delegating that watch to a third party —
answers with the record for the true latest state $n > i$. The high-water mark advances to $n$ and the window refreshes; at its close the
arbiter attests $m_n$, *not* $m_i$. The honest party completes the state-$n$ close; the cheat's ciphertext for $m_i$ is never unsealed and its
stale close stays frozen. The cheater gains nothing and the honest party loses nothing.

#figure(
  ```mermaid
  sequenceDiagram
      participant B as Cheating party
      participant K as Arbiter
      participant A as Honest party
      participant M as Monero
      B->>K: present stale record (id, i)
      K->>K: high-water := i, open window
      A->>K: present record (id, n), n greater than i
      K->>K: high-water := n, refresh window
      K->>K: window elapses
      K-->>A: attest m_n only, release sigma over m_n
      A->>A: decrypt omega_n, complete closing signature
      A->>M: broadcast state-n close
  ```,
  caption: [A stale close is frozen, not punished: the arbiter attests only the maximal presented record.],
  kind: image,
) <arbiter_dispute_sequence>

*Watching duty.* Because a dispute is resolved off-chain, a party must watch the arbiter's log for disputes on its channels, just as it
watches the Monero chain for a close. Both duties are delegable to a watchtower, which needs only the channel's funding-output linking tag
and the presentable records; it can never redirect funds, since a close pays the parties' own addresses. Handing the linking tag to a
watchtower grants it exactly one capability — to _recognize_ this channel's close when it lands, and nothing else (@arbiterPrivacy).

== What is public, and to whom <arbiterPrivacy>

The design leaks strikingly little, but "little" is not "nothing", and it is worth being exact about what the general public, a watchtower,
and the arbiter chain can each learn.

/ A completed close on Monero: an ordinary transaction. To anyone who does not already hold the funding output's linking tag $L_F$, it is
  indistinguishable from any other spend — one-time stealth addresses, amounts hidden by confidential transactions, and under FCMP++ the
  spend proven against the whole membership set, publishing only $L_F$ as the double-spend tag and never revealing _which_ output was
  consumed. Monero's base-layer privacy is entirely undisturbed by the arbiter.

/ Holding $L_F$: a _watch capability_ and nothing more. The linking tag is deterministic in the funding output's key and — this being the
  whole point of a Monero key image — cannot be linked back to that output by anyone who does not already hold it. So whoever has $L_F$ can
  recognize the one transaction that closes this channel, and learn nothing else: not the balances, not the addresses, not the identities.
  The parties compute $L_F$ jointly and may delegate it to a watchtower for exactly this recognition duty.

/ The arbiter chain: only `id` (which _commits to_ $L_F$ without revealing it), an update count, and a close-transaction hash — never $L_F$,
  the balances, or the addresses. A bystander therefore cannot find the Monero close from the arbiter chain: `id` is opaque, and without
  $L_F$ one cannot scan for it. The one residual leak is dispute-path metadata — that some opaque channel was adjudicated, and the update
  count it reached — carrying no identities and no link to Monero, and never arising on the cooperative path.

#note[
  If even that metadata is too much, two independent hardenings are available, neither on by default. The update count need only be
  _monotonically increasing_, not a strict increment, so states can be numbered sparsely ($i in {0, 1, 135, 34873, dots.h}$) and the
  high-water mark then reveals only the last label reached, not how many updates occurred. And where a deployment needs an external verifier
  (a watchtower or auditor) to confirm that a given close matches a given record _without being handed the opening_, the id's commitment to
  $L_F$ (@channelId) can use a proof-friendly scheme such as a Pedersen commitment, so that binding is provable in zero knowledge; the id is
  already blinded by its per-channel nonces, so this buys provability, not hiding.
]

== Trust and collusion

Everything the arbiter guarantees rests on *two platform boundaries*. The first is the validator set staying below its
Byzantine-fault-tolerance threshold: below it, the published state machine (and only it) executes, and the master key $z$ stays
confidential. The second — quieter, and often _lower_ — is governance over the subnet that actually holds $z$: whoever can reshare that key
onto a new node set, or replace the code that runs beside it, inherits the arbiter's authority without crossing the first threshold (the
upgrade path below). What there is _not_ is a second, channel-specific secret, because the design has deliberately left none.

Consider the worst case: enough of the committee is corrupt to attest an arbitrary statement, or the master key $z$ leaks outright. What can
an attacker do? Attest some $m_i$ for a stale state and hand the released key to a colluding party, who completes that state's close. That
is the whole attack surface. It cannot fabricate a state (there is no verifiably encrypted offset and no cross-signed record for a state the parties never
built), cannot alter balances (the close template is fixed at update time), and cannot reach any channel where it lacks a colluding party
(completing a close still needs that party's own funding signature). The reachable damage is a rollback to *some past state both parties
actually signed* — never an arbitrary theft. On the honest execution path it is also *public and attributable*: every honest attestation is
logged before it is usable, and every completed close appears on-chain against $L_F$ — in view of whoever holds it (the parties and any
watchtower they appointed; @arbiterPrivacy), against which a release that does not match the deterministic high-water logic stands out as a
deviation. This loudness is a property of honest execution rather than an unconditional one: because the platform delivers the attestation
encrypted to the requester rather than broadcasting it, a committee already corrupt enough to sign — or a captured governance layer — can
derive a key off-chain and bypass the log. The guarantee thus deters an honest-but-curious operator and records the honest path faithfully;
it does not by itself bind an attacker at or above the threshold. Even so it improves on a custody-based escrow, whose bad release is an
_off-protocol_ handover that leaves no trace on _any_ path, detectable only by the fraud-proof-and-bond machinery such a design must add for
the purpose.

#caution[
  *The upgrade path is the sharp edge.* The arbiter's honesty is the honesty of its code, so whoever can _change the code_ inherits its
  authority. If the deployed program can be replaced while keeping the same on-chain identity — and therefore the same derived attestation
  key — an operator could swap in logic that attests any statement it likes. Removing that path — making the program immutable once fixed,
  or placing control under a decentralized governance body rather than a single operator — is necessary but not sufficient on its own.
  Because the threshold key is held by the platform's validator subnet, not by the program, freezing the program does not remove the
  platform's own power to reshare that key onto a new node set or change the code running beside it. Governance over the key-holding subnet
  must therefore be decentralized and audited too; otherwise a deployment has not removed the trusted secret, only moved it up a layer.
]

#figure(
  caption: [What each failure mode costs.],
  kind: table,
  table(
    columns: 2,
    align: (left, left),
    table.header([*Failure*], [*Consequence*]),
    [Arbiter honest, one party cheats], [Stale close frozen; honest close proceeds. No loss.],
    [Arbiter halts (liveness only)],
    [Honest close waits for cooperation; funds are never at risk. A time-beacon extension could restore liveness at a penalty-channel cost
      (@extensions).],

    [Committee compromised *and* a channel party colludes],
    [Rollback to a _past party-signed state_ on that channel; on-chain, and logged on the honest path, but a threshold-compromised committee
      can derive the key off-chain.],

    [Committee compromised, no colluding party], [Nothing on that channel — the funding signature is still missing.],
    [Deployment or platform governance captured],
    [Full arbiter authority — the reason to decentralize governance over the key-holding subnet, not only the program.],
  ),
) <arbiterFailures>

== Instantiation on the Internet Computer <icp>

The Internet Computer's _vetKeys_ feature (exposed as vetKD, verifiably encrypted threshold key derivation) is a production realization of
exactly the primitive @attestation needs: a validator set that holds a stable threshold-BLS master key on curve `bls12_381_g2` and releases
a signature on a caller-supplied, application-chosen byte string, gated by canister logic, and delivered blinded so that only the requester
learns it.

- The management-canister method `vetkd_public_key` returns the stable master (or context-derived) public key $Z$ for a triple
  `(canister, context, key_id)`. The arbiter fixes a `context` and publishes the resulting $Z$; offsets are encrypted against it.
- `vetkd_derive_key` releases the key for a caller-supplied `input` — here `input` $= m_i$ — encrypted under a caller-supplied transport
  key. The canister calls it only when its own state machine has reached "attest the high-water statement" (@onElapsed), so the on-chain
  logic _is_ the gate.
- Canister _timers_ let the state machine self-trigger the window's expiry, so @onElapsed runs autonomously without an external poker.
- The `ic-vetkeys` libraries provide the threshold-signing helpers, and `vetkd_derive_key` yields a genuine, pairable BLS signature
  $sigma_m$. Its shipped identity-based-encryption path, however, is a byte-oriented hybrid scheme, so the verifiably encrypted offset is not that object:
  it is a purpose-built encryption over the released $sigma_m$ that matches @encStmt–@decStmt and admits the binding proof.
- The optional fee-and-deposit bond (@arbiterFees) falls out for free: a canister holds and moves value natively (its own cycles or an
  ICRC-1 token), so registration can gate on an ICRC-1 transfer of $d_k + f_k$ from $B$, the fee is credited to the committee's treasury,
  and the same deterministic state machine that attests the high-water statement also pays the deposit to the winner (or refunds it to $B$
  on a cooperative-close cleanup call). No new trust is introduced — only the vetKD attestation is security-critical, and it is untouched.

#note[
  Two integration details carry real weight. The offset is encrypted on the Monero/Ed25519 side and decrypted with a BLS12-381 key, so the
  group placement, point serialization, and especially the hash-to-curve derivation — which augments the hashed statement with the derived
  public key — must be reproduced exactly by the party-side encryptor. And the deployment must fix its upgrade path, and decentralize
  governance over the key-holding subnet, before it holds real value.
]

The two boundaries of the previous section fall, for ICP, like this: the key is held by the _subnet_ the canister runs on — on the order of
34 nodes, with forging a signature requiring a two-thirds quorum — and the _Network Nervous System_ governs that subnet's membership, its
replica code, and the re-sharing that keeps the key alive, at a threshold that can sit below the subnet's own. Closing that second boundary
— decentralizing the governance, or accepting an immutable canister and its loss of patchability — is the deployment's real work. ICP is not
the only platform that could host the arbiter; Fairblock, dcipher and Sui's Seal expose comparable threshold identity-based encryption. It
is the turnkey option: it custodies value and self-triggers natively, and it is live on mainnet with a completed external audit.

== Optional: fees, deposits, and cleanup <arbiterFees>

This mechanism is _optional_: a deployment that wants the arbiter to hold no value at all omits it. Where it is used, it lets the arbiter
charge for its service and gives the parties a bond that makes the cooperative path the cheapest one.

At channel setup, a _deposit_ $d_k = d_a + d_b$ and a _fee_ $f_k$ are lodged with the arbiter contract in the arbiter chain's own currency.
On the common paths only the merchant $B$ touches that currency: $B$ fronts the whole $d_k + f_k$, and the customer $A$ reimburses her share
$d_a <= d_k$ _across the Monero channel_ as an ordinary in-channel payment. So each party bears its own portion of the bond while $A$ need
not hold the arbiter chain's token to open a channel. The arbiter keeps $f_k$ as revenue and holds $d_k$ until the channel resolves,
releasing it as follows:

/ Cooperative close (the common path): $B$ presents the cooperatively-signed final state — which $A$ signed, and which already accounts for
  the $d_a$ paid through the channel — and the arbiter refunds $d_k$ to $B$ and tombstones the channel. Reclaiming the bond is exactly what
  incentivizes $B$ to return and clear per-channel state rather than leave stale disputes cluttering the arbiter chain.

/ Adjudicated close: the arbiter pays $d_k$ to the _winner_ — the party that presented the maximal record — at the window's close. Because
  the winner is always the honest closer, whoever forced the dispute (by cheating or by going silent) forfeits their share to the party that
  behaved. This is a mild, bounded nudge toward cooperation, not a capacity-sized penalty.

#note[
  Taking part in a dispute — presenting a higher record, or claiming the deposit as winner — does require $A$ to talk to the arbiter chain
  and receive a payout on it. The dispute path is already interactive and rare, so an $A$ that anticipates needing it keeps a minimal
  arbiter-chain presence or delegates both the watch and the claim to a watchtower, which can act for her without ever redirecting channel
  funds.
]

The bond is _value on the arbiter chain, not a channel secret_. A compromised arbiter can at worst misdirect a bond — an amount
bounded by $d_k$, chosen small, and visibly on the arbiter chain — never the Monero funds, which still need a party's own funding signature
and the true offset. The custody-free property concerns channel secrets, of which the arbiter still holds none; a small, bounded, on-chain
bond is a categorically smaller exposure.

== Possible extensions <extensions>

The core design is deliberately minimal, and two directions extend it — each buying something real at a cost worth stating before it is
adopted.

/ A time-beacon liveness backstop: An arbiter halt costs liveness (@arbiterFailures): an honest close waits until the counterparty
  cooperates. To survive a halt _without_ the counterparty, each verifiably encrypted offset can be composed so that it opens under _either_ condition —
  the arbiter attests $m_i$, *or* a public randomness beacon reaches a pre-agreed round. The price, though, is the whole price of a penalty
  channel. A time branch cannot know which state is latest, so it opens _every_ state's offset, stale ones included — and the offset is the
  same object whether its state turns out latest or stale, fixed when the ciphertext is sealed. A patient cheater need only wait for an old
  state's beacon round to pass and then race an honest close onto the chain; making that race safe pulls in the full standalone regime —
  collateral roughly equal to the channel capacity, a bounded channel lifetime, and a re-gating schedule so the latest state matures first.
  Beacon openings are also silent, leaving no entry in the arbiter's log. It is a heavyweight option, suited only to channels that must
  survive an arbiter halt and can afford capacity-sized collateral; the default deployment omits it.

/ Proof-friendly commitments and sparse numbering: The privacy hardenings of @arbiterPrivacy are extensions in the same sense — numbering
  states sparsely hides the update count, and a proof-friendly commitment of `id` to $L_F$ lets an external verifier check a close against a
  record in zero knowledge. Neither is on by default, and neither changes the core safety argument.

== Summary

The arbiter is a deterministic dispute state machine that holds no share of the funding key and no per-channel secret. It keeps a high-water
mark, an adjudication window, a tombstone, and a public log, and its only power is to attest one statement — the true latest state — which
unseals exactly the offset that closes at it. A stale close is frozen rather than punished, so cheating cannot pay. Trust reduces to two
platform boundaries — the validator set's fault threshold and governance over the key-holding subnet; the worst residual failure is a
bounded rollback to a past state both parties signed, public and attributable on the honest execution path, and only with a colluding
channel party. It leaks strikingly little — the arbiter never sees balances, addresses, or the funding output's linking tag in the clear,
and a bystander cannot link its opaque records to a Monero close. An optional fee-and-deposit bond funds the service and rewards cooperation
without ever holding a channel secret, and a time-beacon extension (@extensions) can trade capacity-sized collateral for survival of an
arbiter halt. Instantiated on a consensus-held threshold-BLS key, with the deployment's upgrade path closed, the arbiter gives Grease fair
dispute resolution without ever asking anyone to hold a secret whose leak would matter.
