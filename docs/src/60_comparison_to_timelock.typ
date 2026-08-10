// Preamble
#import "@preview/note-me:0.5.0": *
#import "metadata/nomenclature.typ": *

= Comparison with a timelock-based channel <timelockComparison>

Monero Research Lab #link("https://github.com/monero-project/research-lab/issues/161")[issue 161] ("I161", tevador, 2026) proposes
adding *relative locks* to Monero on top of FCMP++, and sketches a bidirectional payment channel built on them. The channel needs no
third party of any kind: its dispute mechanism is enforced entirely by Monero consensus. The price is a hard fork — the relative lock is
a new consensus rule — and at the time of writing the proposal's fate is undecided (the concrete suggestion on the table is to _reserve_
`unlock_time = 1` at the FCMP++ fork without implementing the lock).

Grease sits at the opposite corner: it needs no consensus changes at all, but delegates dispute resolution to the arbiter of
@arbiterDesign. This chapter examines the middle ground: *running I161's transaction graph, but replacing the relative lock with the
arbiter's sealed-offset mechanism*. We call this combination _the hybrid_ throughout. The questions it answers: is the hybrid feasible;
how does it work; is it simpler or more complicated than Grease; and what does it gain and lose against the Grease design.

To stay close to the source material, this chapter uses I161's party names, Alice and Bob, rather than customer and merchant. Fees are
ignored except where they matter.

== The I161 channel, step by step <i161Protocol>

=== The relative lock it is built on

I161 changes what a lock _is_. The legacy `unlock_time` locked outputs; the proposed lock applies to *transaction inclusion* — a locked
transaction cannot even enter the mempool until it unlocks. In the simplest variant, a transaction signed with `unlock_time = 1` is
forced by consensus to build its FCMP++ membership proof against the tree root from 720 blocks before its reference height. Spending an
output of transaction $X$ requires a tree that contains $X$, so the spending transaction cannot be mined until 720 blocks (about 24
hours) after $X$ confirms — whenever that turns out to be. That is a relative lock: the clock starts when the parent lands.

=== Opening the channel

Alice and Bob jointly prepare four transactions. Only *Fund* is broadcast.

+ Agree the initial balances.
+ Agree a 2-of-2 address $K^"fund"$ (the channel's funds) and a 2-of-2 address $K^"close"_0$.
+ Jointly sign *Recover(0)*: it spends $K^"close"_0$ to Alice's and Bob's own addresses at the state-0 balances. It is fully signed, but
  relative-locked 720 blocks behind the *Close* transaction that will create its input.
+ Alice shares a fresh public key $T^A_0$; Bob shares $T^B_0$.
+ Alice signs her half of *CloseB(0)* ($K^"fund" -> K^"close"_0$, the entire balance) using the nonce $R + T^B_0$. Only Bob, who knows
  the secret $t^B_0$, can finish this signature — and the finished signature, once on chain, hands $t^B_0$ to Alice.
+ Bob signs his half of *CloseA(0)* the same way against $T^A_0$. Only Alice can finish it, and broadcasting it reveals $t^A_0$ to Bob.
+ Jointly sign *Fund* and broadcast it.

```
                  [Fund]  (on chain)
                     |  pays K_fund (2-of-2)
         +-----------+-----------+
         v                       v
   [CloseA(0)]             [CloseB(0)]      off-chain; adaptor-signed:
   only Alice can          only Bob can     finishing + broadcasting one
   finish it               finish it        reveals t_A0 / t_B0 to the peer
         |                       |
         +-----------+-----------+
                     v  spends K_close_0
               [Recover(0)]                 fully signed, but cannot be mined
               pays state-0 balances        until 720 blocks after the Close
                                            that created its input
```

There are two Close variants only so that _either_ party can close alone. Both pay the whole balance to the same $K^"close"_0$, and
since they spend the same input, at most one can ever confirm.

=== Updating the channel (state $N-1 -> N$)

+ Agree new balances and a fresh $K^"close"_N$.
+ Jointly sign *Recover(N)* ($K^"close"_N ->$ the new balances, relative-locked as before).
+ Exchange fresh keys $T^A_N$, $T^B_N$; adaptor-sign *CloseA(N)* and *CloseB(N)* exactly as at opening.
+ Revoke state $N-1$ by exchanging punishment signatures:
  - Alice signs *PunishA(N)*: it spends $K^"close"_(N-1)$ and pays the _entire_ balance to Bob. She uses the nonce $R + T^A_(N-1)$ but
    leaves $t^A_(N-1)$ out of her response, so the signature is invalid as handed over.
  - Bob signs *PunishB(N)* symmetrically: it spends $K^"close"_(N-1)$, pays everything to Alice, and is invalid without $t^B_(N-1)$.

The point of the last step: if Alice ever broadcasts the stale *CloseA(N−1)*, its completed signature publishes $t^A_(N-1)$ on chain.
Bob adds that value to the invalid *PunishA(N)* he has been holding, and it becomes a valid transaction paying him the whole channel.
The stale close itself is what arms the punishment; nothing is handed over at revocation time beyond the two invalid signatures.

```
                  [Fund]
                     |
         +-----------+------------+
         v                        v
   [CloseA(N-1)]           [CloseB(N-1)]     <- now stale
         |                        |
         +-----------+------------+
                     v  K_close_(N-1)
        +------------+--------------+
        v            v              v
 [Recover(N-1)] [PunishA(N)]  [PunishB(N)]
  locked 720     no lock:      no lock:
  blocks         Bob's, armed  Alice's, armed
                 by t_A(N-1)   by t_B(N-1)

   ...and the fresh state:  [CloseA(N)] / [CloseB(N)] -> [Recover(N), locked]
```

=== Closing, three ways

#figure(
  caption: [The three ways an I161 channel closes.],
  kind: table,
  table(
    columns: 3,
    align: (left, left, left),
    table.header([*Close type*], [*What happens*], [*On chain*]),
    [Cooperative], [Jointly sign a fresh *Withdraw* at the final balances], [Fund, Withdraw],
    [Undisputed force close], [One party broadcasts *Close(N)*, waits 24 hours, broadcasts *Recover(N)*], [Fund, Close, Recover],
    [Disputed force close], [A stale *Close(i)* is answered with *Punish(i+1)*], [Fund, Close, Punish],
  ),
) <i161Closes>

The disputed case, as a sequence:

#figure(
  ```mermaid
  sequenceDiagram
      participant A as Cheating Alice
      participant M as Monero
      participant B as Honest Bob
      A->>M: broadcast stale CloseA(i)
      M-->>B: CloseA(i) confirms, publishing t_A(i)
      B->>B: add t_A(i) to the stored PunishA(i+1)
      B->>M: broadcast PunishA(i+1), mineable at Close + 10 blocks
      A->>A: Recover(i) locked for another 710 blocks
      M-->>B: Punish confirms and pays Bob the entire channel balance
  ```,
  caption: [I161's disputed force close. The 720-block lock on Recover against the 10-block default lock on Punish is the honest
    party's entire protection.],
  kind: image,
) <i161DisputeSeq>

=== Why the lock is the whole trick

*Recover(i)* is _fully signed_ at update time. The only thing standing between a cheater and a successful rollback is that Recover
cannot be mined for 720 blocks while Punish can be mined after 10. That 710-block head start is the honest party's entire protection.
Remove the lock and Recover(i) becomes mineable at the same moment as Punish — the race becomes a coin toss and the design collapses.
So any lock replacement must answer exactly one question: *what else can hold Recover(i) back?*

== Where the Grease mechanism fits <i161Hybrid>

Assume relative locks are _not_ added at or after the FCMP++ fork. The hybrid keeps I161's four-transaction graph and answers the
question above with the machinery of @arbiterDesign, unchanged: an offset sealed to a statement, released only when the arbiter attests
that statement, where the arbiter attests only the newest state anyone presents (@attestation, @stateMachine).

=== The substitution: seal Recover's completion, leave Punish alone

One change is made to the graph: *Recover(N) is no longer fully signed.* As with Grease's commitment transaction (@updateProtocol),
each party's copy of Recover(N) carries the counterparty's adaptor signature, deliberately incomplete, missing a fresh offset
$omega_N$. Each party hands the other that offset encrypted to the statement $m_N = (#raw("id"), N)$ under the arbiter's stable key,
together with the binding proof of @bindingProof. The only way to complete Recover(N) without the counterparty's cooperation is an
arbiter attestation of $m_N$ — and a stale state's statement is never attested once a newer record has been presented.

Punish is untouched: no lock, no sealed offset, no arbiter. It is armed by the $t$ value that a stale Close publishes on chain, exactly
as in I161.

```
                  [Fund]  (on chain)
                     |
         +-----------+-----------+
         v                       v
   [CloseA(N)]             [CloseB(N)]      unchanged from I161:
    T-adaptor,              T-adaptor,      broadcasting one reveals
    Alice finishes          Bob finishes    its t value to the peer
         |                       |
         +-----------+-----------+
                     v
               [Recover(N)]                 CHANGED: each party's copy is an
    missing offset omega_N, held by         incomplete adaptor signature;
    the counterparty encrypted to           completing it requires the arbiter
    m_N = (id, N)                           to attest m_N, i.e. that N is the
                                            newest state presented

   [PunishA(N)] / [PunishB(N)]              unchanged from I161: no lock,
    spend K_close_(N-1), pay everything     armed by the t that a stale
    to the wronged party                    Close publishes
```

Two adaptor mechanisms coexist without interfering, doing different jobs:

- the *$T$-adaptors on Close* exist so that _broadcasting_ a close publishes a secret — the punishment trigger;
- the *$omega$-offsets on Recover* exist so that a public attestation decides _which_ state's recovery can ever be completed — the
  delay.

Both are ordinary Schnorr adaptor signatures and run on the FROST 2-of-2 machinery Grease already has (@walletTxProtocol); whether the
missing piece sits in the nonce (I161's style) or the response (Grease's style) is bookkeeping, not cryptography.

All of Grease's establishment work carries over unchanged, and is in fact _required_: the arbiter statement needs a channel id, and the
id must commit to the funding outputs through their linking tags — so the funding declaration, the out-proofs, and the linking-tag
exchange with its DLEQ all stay (@initProtocol, @linkingTagExchange, @channelId). The cross-signed `UpdateRecord` also stays, with one
adjustment: its `close_hash` field commits to *Recover(N)* — the transaction whose completion the attestation controls — rather than to
the Close.

=== Why Recover is the only workable place for the seal

/ Seal the Close instead?: A stale Close could then never be broadcast at all — but then its $t$ is never published, Punish never arms,
  and the Close/Recover/Punish structure does nothing. This collapses back into plain Grease with a pointless extra transaction in the
  middle.

/ Seal the Punish?: Backwards. The honest party would need an attestation — a matter of hours — inside the 10-block head start before
  the cheater's Recover becomes mineable. Fails outright.

/ Imitate the relative lock with time-based IBE?: Encrypting the offset to a future randomness-beacon round fails structurally: a
  beacon fires at an _absolute_ time, but the lock must run _from the moment the Close lands_, which nobody knows at signing time. This
  is the same obstacle @extensions runs into for the time-beacon liveness fallback.

So the hybrid has exactly one degree of freedom, and it is forced: the seal goes on Recover.

=== The closing paths, revisited

/ Cooperative close: Unchanged from both designs — one ordinary transaction from $K^"fund"$; no Close, no Recover, no arbiter contact
  (@coopClose).

/ Undisputed force close: The counterparty is silent but nobody has cheated. Alice broadcasts *Close(n)* for the latest state, presents
  her record for $n$ to the arbiter, waits out the adjudication window, decrypts $omega_n$ from the attestation, completes *Recover(n)*
  and broadcasts it. Three on-chain transactions; the total delay is the arbiter window plus confirmations — comparable to I161's 24
  hours and to Grease's own dispute path (@disputeFlow).

/ Disputed force close: The counterparty broadcast a stale *Close(i)*. The honest party has two independent answers, and needs only the
  first:
  + *Punish* — extract $t$ from the stale close on chain, complete Punish(i+1), broadcast it. It is mineable 10 blocks after the Close.
    _The arbiter is not involved at all._
  + *Answer the dispute* — the cheater cannot complete Recover(i) without $omega_i$, so they must open a public arbiter dispute at
    state $i$; the honest party (or its watchtower) answers with the record for $n > i$, the high-water mark rises, and $omega_i$ is
    never released. This is insurance only: once Punish confirms, Recover(i) is spending an output that no longer exists.

#figure(
  ```mermaid
  sequenceDiagram
      participant A as Cheating Alice
      participant K as Arbiter
      participant B as Honest Bob
      participant M as Monero
      A->>M: broadcast stale CloseA(i), publishing t_A(i)
      B->>M: complete and broadcast PunishA(i+1)
      A->>K: present record (id, i), hoping to unseal omega_B(i)
      K->>K: high-water := i, open window of hours, publicly logged
      B->>K: insurance, present record (id, n), n greater than i
      K->>K: high-water := n
      M-->>B: PunishA(i+1) confirms, Bob holds the entire balance
      K-->>B: window ends, attest m_n only, omega_B(i) never released
  ```,
  caption: [The hybrid's disputed force close. Punish resolves the cheat on Monero alone; the arbiter path is a second, independent
    barrier in front of the cheater's Recover.],
  kind: image,
) <hybridDisputeSeq>

Note what moved relative to plain Grease: when a stale close hits the chain, the honest remedy is Punish, not the arbiter. The
arbiter's remaining jobs are the silent-counterparty close and, as insurance, refusing the cheater's decryption request.

=== The delay on the cheater's Recover, compared

#figure(
  caption: [What holds back a cheater's Recover(i) in each regime.],
  kind: table,
  table(
    columns: 3,
    align: (left, left, left),
    table.header([*Regime*], [*What delays Recover(i)*], [*Honest party's margin*]),
    [I161 (relative locks)], [Consensus: not mineable for 720 blocks], [710 blocks (about 24 h), unconditional],
    [Hybrid, honest arbiter],
    [Needs an attestation of $m_i$: a public dispute plus a window of hours — never granted once the record for $n$ is presented],
    [Punish is effectively unopposed],

    [Hybrid, committee compromised _and_ counterparty colluding],
    [Attestation derived silently in advance; Recover(i) mineable at Close + 10],
    [A race of about 10 blocks (20 min)],

    [Grease, committee compromised _and_ counterparty colluding],
    [Nothing — the stale close is completed silently off-chain and broadcast finished],
    [None; the rollback simply succeeds],
  ),
) <recoverDelays>

The third row is the hybrid's one weakened property against I161; the fourth row is why that weakness is still a large improvement over
plain Grease (@i161Advantages). Two mitigations for the third row cost nothing: pre-sign $"fee"("Punish") > "fee"("Recover")$ so miners
prefer the punishment in a direct race, and — should a later hard fork provide relative locks after all — put the lock back on Recover,
which restores I161's unconditional ordering (@recoverCondition).

=== Update ordering and the half-finished update

Within an update, the exchange runs: the new Close adaptor signatures and the sealed Recover offsets with their binding proofs; the
cross-signed record for $N$; _then_ the two punishment signatures for $N-1$. The I161 discussion thread raised two concerns here:
nothing of real-world value should change hands before an update fully completes, and a party might accept the counterparty's
punishment signature and then refuse to send its own.

The hybrid is more robust in this window than plain I161. If the punishment exchange stalls half-done, either party can still
force-close safely at state $N$ — the Close and Recover material is already complete. And a stale close by the stalling party during
the window, while not punishable, is still _unprofitable_: the honest party answers the dispute with the record for $N$, the old offset
is never released, and the cheater's Recover is stuck — the cheat wrecks the channel for both parties rather than paying. The
operational rule stays as the thread stated it: treat the update as done, and release goods, only after the punishment signatures for
$N-1$ have been exchanged both ways.

=== Feasibility checks

#figure(
  caption: [Feasibility checks for the hybrid.],
  kind: table,
  table(
    columns: 2,
    align: (left, left),
    table.header([*Concern*], [*Verdict*]),
    [Pre-signing Recover(N) against $K^"close"_N$, the output of a transaction that has never been broadcast],
    [OK. FCMP++ needs an output _determined_, not mined; membership proofs are built at broadcast time. Grease already relies on
      exactly this to sign exits before funding (@preSigning). Note it is now two levels of chaining (Fund → Close → Recover) rather
      than one.],

    [Does the binding proof carry over?],
    [Yes, unchanged. It binds a ciphertext to whatever adaptor point it is given; Recover's adaptor point plays the role the commitment
      transaction's did.],

    [The open FCMP++ SA+L question — which second base the offset is proven against (@bindingProof)],
    [Still open, and slightly harder here, because the sealed spend now consumes an output of an unbroadcast transaction. The proof
      needs that output determined at update time, which it is; but this is the one item to settle before committing to the design.],

    [CloseA(N) and CloseB(N) must pay a byte-identical $K^"close"_N$ output so that one Recover(N) serves both],
    [OK — they share a body and differ only in whose adaptor completes the input signature; they spend the same input, so at most one
      confirms.],

    [Fixed fees on long-lived pre-signed transactions],
    [The usual staleness risk for pre-signed transactions; no different from Grease.],
  ),
) <hybridFeasibility>

*Verdict: feasible.* No new cryptography beyond what Grease already specifies, and no consensus changes. The one genuine unknown — the
SA+L base composition — is inherited from Grease, not created here.

== Simpler or more complicated? <i161Complexity>

#figure(
  caption: [The hybrid against Grease, phase by phase.],
  kind: table,
  table(
    columns: 4,
    align: (left, left, left, left),
    table.header([*Phase*], [*Grease*], [*Hybrid*], [*Delta*]),
    [Establishment],
    [FROST wallet, funding declaration and out-proofs, channel id, linking tags with DLEQ, state-0 exits],
    [The same, with a state-0 Close/Recover pair in place of the simple exits],
    [about equal],

    [Update],
    [Two adaptor signatures on the commitment transaction, two sealed offsets with binding proofs (23,641 bytes each way, @proofSize),
      one record],
    [The same sealed-offset work, moved onto Recover, _plus_ two Close adaptor signatures, fresh $T$ keys, two punishment signatures
      for $N-1$, and a fresh $K^"close"_N$],
    [about twice the signing; same dominant bandwidth],

    [Cooperative close], [One transaction], [One transaction], [equal],
    [Force close, honest], [Two on-chain transactions, one arbiter dispute], [Three on-chain transactions, one arbiter dispute],
    [one extra transaction],

    [Cheat response], [Answer the dispute within the window (arbiter only)],
    [Broadcast Punish (Monero only); answering the dispute is optional insurance], [different; arguably simpler],

    [Long-term storage], [Latest record and offsets; $O(1)$], [The same, _plus_ punishment material for every past state; $O(N)$,
      none of it losable], [strictly worse],

    [Watchtower needs], [Funding linking tag and the latest record], [Per-state punishment blobs, Lightning-style], [strictly worse],
  ),
) <hybridComplexity>

The honest summary: *nothing from Grease is removed, and I161's transaction graph is added on top.* The wallet, the establishment
protocol, the sealed offsets, the binding proof per direction per update, the arbiter state machine, and both watching duties all
remain. The additions are a second pre-signed transaction level, per-state punishment signatures, and permanent revocation storage.

So the hybrid is *not simpler than Grease — it is Grease plus a Lightning-style penalty layer*. It is also much more complicated than
plain I161, whose entire simplicity ("only adaptor signatures and relative locks, no new cryptography") comes from the
consensus-enforced lock the hybrid is doing without.

Where it _is_ simpler is conceptual rather than mechanical: the response to an on-chain cheat needs only a Monero watcher and one
transaction, with no arbiter interaction, no window, and no deadline measured in anything shorter than hours.

== Advantages over the pure Grease design <i161Advantages>

+ *Cheating is punished, not merely frozen.* In Grease a stale close attempt costs the cheater nothing — it fails, and the honest close
  proceeds. In the hybrid it costs the cheater the entire channel balance, in XMR, immediately. Grease's optional arbiter-chain deposit
  (@arbiterFees) provides a small, bounded deterrent; this one is capacity-sized and needs no second currency.

+ *It blunts Grease's worst admitted failure.* Grease concedes that a compromised committee plus a colluding channel party can roll a
  channel back to a past signed state _silently_ — the attestation can be derived off-chain, leaving no log entry (@arbiterFailures).
  In the hybrid, that same attack requires the colluding party to broadcast a stale Close, which publishes its $t$ on the Monero chain
  — and the honest party punishes with the arbiter entirely out of the loop. The silent, unanswerable rollback becomes a noisy race of
  about 20 minutes that the honest party, helped by a pre-arranged fee advantage, usually wins. Not a proof of safety, but a large
  reduction in the damage ceiling of the design's weakest point.

+ *Two independent defences instead of one.* In Grease, an honest party that misses the adjudication window — offline, censored on the
  arbiter chain, watchtower failure — loses the balance difference to a stale record. In the hybrid, a party that watches only the
  Monero chain still defeats any on-chain cheat via Punish. Each mechanism covers the other's weak spot: the arbiter handles silent
  counterparties; Punish handles broadcast cheats.

+ *An arbiter-liveness fallback becomes affordable.* Grease rejects an "attestation _or_ beacon-round" release for its offsets because
  a time-based branch eventually opens _stale_ offsets too, and making that safe carries the whole price of a penalty channel —
  collateral roughly equal to the channel capacity (@extensions). The hybrid has already paid that price: a patient cheater who waits
  out a beacon branch and broadcasts a stale Close simply gets punished. So the hybrid can add what Grease cannot — a channel that
  survives a permanent arbiter halt without the counterparty's cooperation.

+ *Cheat resolution is faster and cheaper.* About 20 minutes and one Monero transaction, against an adjudication window of hours plus
  arbiter-chain interaction and fees.

+ *Force closes are attributable.* The published $t$ identifies which party broadcast which close — useful where reputation matters.

+ *A clean upgrade path to full trustlessness.* The entire difference between the hybrid and plain I161 is one rule about one
  transaction:

  #figure(
    caption: [The single rule that separates the hybrid from plain I161.],
    kind: table,
    table(
      columns: 2,
      align: (left, left),
      table.header([*Design*], [*When may Recover(i) be broadcast?*]),
      [Hybrid], [When the arbiter has attested $m_i = (#raw("id"), i)$, releasing $omega_i$],
      [I161], [720 blocks after Close(i) confirms (`unlock_time = 1`)],
    ),
  ) <recoverCondition>

  If a later hard fork adds relative locks, an implementation migrates by swapping that one rule — a `RecoverCondition` chosen at
  channel negotiation — deleting the binding proofs (23,641 bytes per direction per update), and retiring the arbiter: the transaction
  graph, the punishment logic and the storage model are already I161's. Plain Grease has no such path; reaching I161 from it is a
  redesign. During a transition, requiring _both_ conditions at once is safe and strictly stronger than either.

== Disadvantages <i161Disadvantages>

+ *Old states become toxic, and revocation material lives forever.* Grease keeps essentially one thing — the latest record and offsets
  — and a stale state there is inert. The hybrid must retain, for _every_ past state, the counterparty's punishment signature, the
  transaction template, and the $T$ point. Unlike Lightning's shachain, none of it compresses: the revocation secret is never handed
  over (it is published by the cheat itself), so each state needs its own stored counterparty signature. The bytes are small — a few
  hundred per state — but none of them may ever be lost.

+ *Losing revocation material creates a rollback target.* If Alice loses state $i$'s punishment material and Bob broadcasts CloseB(i),
  Alice cannot punish. Her arbiter answer — presenting the record for $n$ — only wrecks the channel for both: Recover(i) stays sealed,
  but Recover(n) is unusable too, since its parent Close(n) can never be mined once $K^"fund"$ is spent. Her rational play is to accept
  the rollback. Grease also degrades under data loss — to the newest state the victim can still present — but it has $O(1)$ critical
  material against the hybrid's $O(N)$, and no funds-stuck-for-both corner.

+ *Honest mistakes are punished like crimes.* A client that force-closes from a stale backup loses the entire channel — Lightning's
  classic `channel.backup` failure mode. In Grease the same mistake is harmless: the stale attempt freezes, the latest state closes,
  and nobody loses anything. This is the direct price of the first advantage; punishment cannot distinguish malice from a
  restored-from-backup bug.

+ *One more on-chain transaction per force close* — Fund, Close, Recover against Grease's funding and close: more fees, more chain
  footprint, and one more pre-signed transaction whose fee can go stale.

+ *Heavier updates.* Two extra adaptor-signed transactions, a fresh $T$ keypair exchange, and two punishment signatures per update —
  roughly double the signing rounds, though the binding proofs still dominate bandwidth in both designs.

+ *A new must-not-fail duty on the update path.* The punishment-signature exchange adds a half-finished window with its own rule — no
  goods before both punishment signatures land (@i161Hybrid). The frozen-offset backstop makes cheating in that window unprofitable,
  but the protocol has more states in which a stall needs handling than Grease's single-exchange update.

+ *Heavier watchtowers.* Per-state punishment blobs and a Monero-chain response duty, instead of Grease's "one linking tag plus the
  latest record" (@arbiterPrivacy).

+ *Deeper reliance on unsettled FCMP++ details.* Two levels of pre-signed chaining off unbroadcast transactions, and the open SA+L
  base-composition question now applies to a spend of an unbroadcast output (@hybridFeasibility). Shared with Grease in kind, but
  pushed further.

#note[
  *Status.* The hybrid is an analysed design option, not a commitment. Its one technical prerequisite beyond Grease itself is the open
  SA+L base-composition item of @bindingProof, extended to spends of unbroadcast outputs; that should be settled before any
  implementation work. Its strongest arguments are the second and fourth advantages — hardening the compromised-committee failure mode,
  and making an arbiter-halt fallback affordable — and the migration rule of @recoverCondition, which makes it the only design in this
  document from which a trustless, hard-fork-based channel is a one-rule change rather than a redesign.
]
