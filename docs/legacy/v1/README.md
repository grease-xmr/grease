# Grease v1 whitepaper (legacy — KES/VCOF era)

This directory is a **frozen snapshot** of the original Grease whitepaper Typst source, from the design
era that predates the trustless *arbiter*. It is kept for reference only and is **not maintained**.

## Provenance

- Recovered verbatim from commit **`3e7af2b`** (`chore: save grease whitepaper v1`), which is the parent
  of **`58dc812`** (`docs: arbiter-based design`) — i.e. the last commit before the arbiter redesign
  removed the KES/VCOF material from the live whitepaper.
- Rendered v1 PDF: [`../grease_whitepaper_v1.pdf`](../grease_whitepaper_v1.pdf) (the canonical rendered v1).

## What v1 was

v1 resolved channel disputes with a **Key Escrow Service (KES)** — a third party that held an *encrypted
per-party secret offset* and released the counterparty's offset on dispute — and generated per-update
offsets with a **Verifiable Consecutive One-way Function (VCOF)** whose "consecutiveness" was proven by a
zero-knowledge (SNARK) circuit. v2 replaces **both**: the KES becomes a custody-free **arbiter** that
holds no per-channel secret, and updates use fresh, independent (non-chained) offsets sealed to the
arbiter — so no update-time ZK circuit is needed. See [`../../src/40_arbiter.typ`](../../src/40_arbiter.typ).

## Contents

- `00_grease_whitepaper.typ` — v1 master; `#include`s the chapters below, including the two KES chapters.
- Lifecycle chapters `01`–`18` and `50_limitations.typ` — the **v1 revisions** (the live `docs/src/`
  versions have since been re-framed for the arbiter).
- `40_kes.typ`, `42_trustless_kes.typ` — the v1-exclusive KES design chapters (deleted from `docs/src/`).
- `metadata/` — the v1 `nomenclature.typ`, `front-matter.typ`, and `bibliography.yml`.
- `vcof.typ`, `circuits.typ` — v1 VCOF and ZK-circuit design notes, relocated here from `docs/legacy/`.

## Caveat

This is a *source archive*, not a build target. The master's `#include "../diagrams/…"` lines resolve
against the live `docs/diagrams/` (which has evolved since v1), so recompiling this snapshot may not
reproduce the v1 PDF exactly. Use `../grease_whitepaper_v1.pdf` as the authoritative rendered v1.
