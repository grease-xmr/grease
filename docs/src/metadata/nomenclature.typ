#let pubOf(k, P) = { $#P = #k dot.op G$ }
#let hashOf(alg, input) = { $H_(#alg)(#input)$ }

#let bjj = $"BJJ"$
#let ed = $"Ed"$
#let merchant = $"merchant"$
#let cust = $"customer"$
#let initr = $"Initiator"$
#let respr = $"Responder"$
#let Gbjj = $G_bjj$
#let Ged = $G_ed$
#let Lbjj = $L_bjj$
#let Led = $L_ed$
#let witness = $omega$

// Baby Jubjub points
#let PubBjj(k) = $Pi_#k$

#let nomenclature = {

  table(columns: 2, align: (left, left),
    table.header( [*Symbol*], [*Description*]),
    Gbjj, [Generator point for curve Baby JubJub],
    Ged, [Generator point for curve Ed25519],
    Lbjj, [The prime order of curve Baby JubJub],
    Led, [The prime order for curve Ed25519],
    $witness_i$, [The witness value for party $i$],
    $T_i$, [The public point corresponding to $witness_i$ on curve Baby JubJub],
    $S_i$, [The public point corresponding to $witness_i$ on curve Ed25519],
  )

}

#let subscripts = {
  let peer_types = (
    "merchant": merchant,
    "customer": cust,
    "initiator": initr,
    "responder": respr
  )

  let rows = peer_types.pairs().map(((s,v)) => {
      (v, [The peer playing the role of #s])
  }).flatten()

table(columns: 2, align: (left, left),
    table.header( [*Subscript*], [*Referent*]),
    bjj, [Curve Baby JubJub],
    ed, [Curve Ed25519],
    ..rows

  )
}