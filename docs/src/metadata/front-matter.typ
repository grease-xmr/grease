#import "@preview/lovelace:0.3.0": *

#let format(doc) = {
  set par(
    first-line-indent: 1em,
    justify: true,
  )
  set page(
      paper: "a4",
      margin: (x: 4cm, top: 3cm, bottom: 3cm),
      numbering: "1"
  )
  set text(
    size: 12pt
  )
  set heading(numbering: "1.")
  show heading: set block(below: 1.5em, above: 2em)
  set par(
      leading: 0.6em,
      spacing: 1.25em,
      justify: true
  )
  show link: set text(blue)
  show figure.where(
      kind: table,
  ): set figure.caption(position: top)

  
  doc
}


#let algo(caption: none, title: none, list) = {
  figure(
    caption: caption,
    kind: "algorithm",
    supplement: [Algorithm],
    placement: auto,
    pseudocode-list(booktabs: true, title: title)[#list],
  )
}