#import "@preview/ilm:1.4.1": *
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
#show link: underline

#include "01_introduction.typ"
#include "02_circuits.typ"
#include "03_limitations.typ"

= Nomenclature

== Symbols

#nomenclature

== Subscripts

#subscripts