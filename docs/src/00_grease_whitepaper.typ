#import "@preview/ilm:1.4.1": *
#import "@preview/pintorita:0.1.4"
#import "metadata/nomenclature.typ":*

#let title = "Grease: A Private Payment Channel Protocol for Monero"
#let author = "Grease Team"

#set text(lang: "en")

#show: ilm.with(
  title: title,
  author: author,
  paper-size: "a4",
  date: datetime(year: 2025, month: 07, day: 21),
  bibliography: bibliography("metadata/bibliography.yml", title: "References", full: false, style: "american-medical-association"),
  figure-index: (enabled: true),
  table-index: (enabled: true),
  listing-index: (enabled: true)
)
//#show link: underline
#show link: it => { underline(stroke: (paint: blue, dash: "dashed", thickness: 1pt), it.body) + super[#sym.dagger] }

#show raw.where(lang: "mermaid"): it => pintorita.render(it.text)

#include "01_introduction.typ"
#include "10_channel_design.typ"
#include "12_new_channel.typ"
#include "14_establishing_channel.typ"
#include "15_cooperative_close.typ"
#include "16_channel_dispute.typ"
#include "20_circuits.typ"
#include "30_limitations.typ"
#include "40_kes.typ"

#outline(title: "Table of Algorithms", target: figure.where(kind: "algorithm"))

= Nomenclature

== Symbols

#nomenclature

== Subscripts

#subscripts