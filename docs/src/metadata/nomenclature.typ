#let pubOf(k, P) = { $#P = #k dot.op G$ }
#let hashOf(alg, input) = { $H_(#alg)(#input)$ }


#let bjj = $"BJJ"$
#let ed = $"Ed"$
#let merchant = $"M"$
#let cust = $"C"$
#let initr = $"Initiator"$
#let respr = $"Responder"$
#let Gbjj = $GG_2$
#let Ged = $G_1$
#let Lbjj = $L_2$
#let Led = $L_1$
#let witness = $omega$

// Wallet protocol nomenclature
#let pre(actor) = $C^#actor$
#let preC = $pre(cust)$
#let preM = $pre(merchant)$
#let partialSig(actor,sub) = $(R^(#actor)_(#sub), s^(#actor)_(#sub))$
#let adapterSig(actor,sub) = $(R^(#actor)_(#sub), Q^(#actor)_(#sub), hat(s)^(#actor)_(#sub))$

// Baby Jubjub points
#let PubBjj(k) = $T_#k$

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

// Defined in KES.typ
// master private keys
#let kk = $k_K$
#let kc = $k_C$
#let km = $k_M$
// master public keys
#let Pk = $P_K$
#let Pm = $P_B$
#let Pc = $P_A$

// shared channel secret
#let chs = $kappa$
// kes grease channel secret key
#let kg = $k_g$
// kes grease channel public key
#let Pg = $P_g$
#let hash(alg, input) = { $H_(#alg)(#input)$ }
#let H2F(input) = { $H_F (#input)$ }
#let H2P(input) = { $H_P (#input)$ }
#let Pvcof(sub) = { $Pi^V_(#sub)$ }

#let wn(sub) = { if sub == none { $witness_0$ } else { $witness_#sub$ } }
#let w0 = wn(0)
#let PubWEd(sub) = { $Q_#sub$ }
#let PubWBjj(sub) = { $T_#sub$ }
#let DleqP = $Pi$
#let PokP = $Gamma$