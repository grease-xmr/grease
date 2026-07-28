#let hashOf(alg, input) = { $H_(#alg)(#input)$ }

#let ed = $"Ed"$
#let merchant = $"M"$
#let cust = $"C"$
#let initr = $"Initiator"$
#let respr = $"Responder"$
#let Ged = $G$
#let Led = $N$
#let witness = $omega$

// Wallet protocol nomenclature
#let pre(actor) = $C^#actor$
#let preC = $pre(cust)$
#let preM = $pre(merchant)$
#let partialSig(actor, sub) = $(R^(#actor)_(#sub), s^(#actor)_(#sub))$
#let adapterSig(actor, sub) = $(R^(#actor)_(#sub), Q^(#actor)_(#sub), hat(s)^(#actor)_(#sub))$

#let nomenclature = {
  table(
    columns: 2,
    align: (left, left),
    table.header([*Symbol*], [*Description*]),
    Ged, [Generator point for the Ed25519 curve],
    Led, [The prime order of the Ed25519 group],
    $omega_i$, [The secret adapter-signature offset for channel state $i$],
    $Q_i$, [The public adapter point corresponding to $omega_i$ on Ed25519, $Q_i = omega_i dot.c G$],
    $m_i$, [The dispute statement for state $i$ ("on channel id, state $i$ is the latest")],
    $Z$, [The arbiter committee's stable threshold-BLS master public key, $Z = z dot.c G_2$],
    $sigma_m$, [The arbiter's attestation of a statement $m$: a threshold-BLS signature that acts as the decryption key for $m$],
  )
}

#let subscripts = {
  let peer_types = (
    "merchant": merchant,
    "customer": cust,
    "initiator": initr,
    "responder": respr,
  )

  let rows = peer_types
    .pairs()
    .map(((s, v)) => {
      (v, [The peer playing the role of #s])
    })
    .flatten()

  table(
    columns: 2,
    align: (left, left),
    table.header([*Subscript*], [*Referent*]),
    ed, [Curve Ed25519],
    ..rows,
  )
}

// Party keys
#let Pm = $P_B$
#let Pc = $P_A$

#let hash(alg, input) = { $H_(#alg)(#input)$ }
#let H2F(input) = { $H_F (#input)$ }
#let H2P(input) = { $H_P (#input)$ }

#let wn(sub) = { if sub == none { $witness_0$ } else { $witness_#sub$ } }
#let PubWEd(sub) = { $Q_#sub$ }
