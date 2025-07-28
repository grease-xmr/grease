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
  show heading: set block(below: 1.5em, above: 2em)
  set par(
      leading: 0.6em,
      spacing: 1.25em,
      justify: true
  )
  show link: set text(blue)

  doc
}

#let SMc(content) = {
    box(content)
}