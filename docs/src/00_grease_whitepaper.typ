#import "@preview/ilm:1.4.1": *
#import "@preview/pintorita:0.1.4"
#import "metadata/nomenclature.typ": *

#let title = "Grease: A Private Payment Channel Protocol for Monero"
#let author = "Grease Team"

#set text(lang: "en")

#show: ilm.with(
  title: title,
  author: author,
  paper-size: "a4",
  date: datetime(year: 2026, month: 01, day: 21),
  bibliography: bibliography("metadata/bibliography.yml", title: "References", full: false, style: "american-medical-association"),
  figure-index: (enabled: true),
  table-index: (enabled: true),
  listing-index: (enabled: true),
)

#show raw: set text(font: "Fira Code", size: 8pt)

//#show link: underline
#show link: it => { underline(stroke: (paint: blue, dash: "dashed", thickness: 1pt), it.body) + super[#sym.dagger] }

#show raw.where(lang: "mermaid"): it => {
  let fast_mode = ("fast" in sys.inputs) and (sys.inputs.fast == "1")
  if fast_mode { box(stroke: red, it) } else { pintorita.render(it.text) }
}


#include "01_introduction.typ"
#include "10_channel_design.typ"
#include "12_new_channel.typ"
#include "14_establishing_channel.typ"
#include "15_channel_update.typ"
#include "16_cooperative_close.typ"
#include "18_channel_dispute.typ"
#include "40_kes.typ"
#include "50_limitations.typ"

#outline(title: "Table of Algorithms", target: figure.where(kind: "algorithm"))

= Nomenclature

== Symbols

#nomenclature

== Subscripts

#subscripts
