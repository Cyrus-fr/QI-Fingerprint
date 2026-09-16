---
name: QI-Fingerprint — The Core Log
description: A stratigraphic core log through an ECDSA signature corpus, read top to bottom as a descent.
colors:
  ground: "#232a27"
  ground-raised: "#2c3430"
  rule: "#3a443f"
  rule-strong: "#4d5a54"
  stock: "#dfe4d9"
  stock-rule: "#b9c2b3"
  stock-ink: "#171c19"
  ink: "#e9ede5"
  ink-2: "#a4ae9f"
  ink-3: "#8a9384"
  field: "#6aa9d6"
  field-deep: "#1d5c8a"
  assay: "#d2542f"
  truncated-msb: "#5b9dd9"
  modular-reduction: "#57a87a"
  short-period-prng: "#c2557f"
  weak-seed: "#cf9440"
  clean: "#7d857a"
typography:
  display:
    fontFamily: "Archivo, ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(2rem, 4.2vw, 3.6rem)"
    fontWeight: 700
    lineHeight: 1.02
    letterSpacing: "-0.04em"
  headline:
    fontFamily: "Archivo, ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(1.85rem, 3.4vw, 3rem)"
    fontWeight: 700
    lineHeight: 1.02
    letterSpacing: "-0.035em"
  title:
    fontFamily: "Archivo, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.02em"
  body:
    fontFamily: "Archivo, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.92rem"
    fontWeight: 400
    lineHeight: 1.72
    letterSpacing: "normal"
  reading:
    fontFamily: "Spline Sans Mono, ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "0.78rem"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "-0.01em"
    fontFeature: "tnum 1, zero 1"
  label:
    fontFamily: "Spline Sans Mono, ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "0.65rem"
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: "0.16em"
rounded:
  none: "0px"
spacing:
  gutter: "1.5rem"
  gutter-wide: "3rem"
  rail-inset: "10rem"
  row: "1.75rem"
  interval: "5rem"
  interval-wide: "7rem"
  ruling: "28px"
components:
  interval:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "5rem 1.5rem"
  sheet:
    backgroundColor: "{colors.stock}"
    textColor: "{colors.stock-ink}"
    rounded: "{rounded.none}"
    padding: "1.75rem"
  logged-row:
    backgroundColor: "transparent"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.none}"
    padding: "1.75rem 0.5rem"
  logged-row-hover:
    backgroundColor: "color-mix(in oklab, #6aa9d6 9%, transparent)"
    textColor: "{colors.ink}"
  repro:
    backgroundColor: "transparent"
    textColor: "{colors.field}"
    typography: "{typography.reading}"
    rounded: "{rounded.none}"
    padding: "1rem 0 0"
  repro-on-stock:
    backgroundColor: "transparent"
    textColor: "{colors.field-deep}"
    typography: "{typography.reading}"
  title-block-row:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "0.625rem 0"
  depth-rail-tick:
    backgroundColor: "{colors.rule-strong}"
    textColor: "{colors.ink-3}"
    typography: "{typography.reading}"
    width: "0.5rem"
    height: "1px"
  depth-rail-tick-active:
    backgroundColor: "{colors.field}"
    textColor: "{colors.field}"
    width: "1.5rem"
    height: "1px"
  assay-rule:
    backgroundColor: "{colors.assay}"
    rounded: "{rounded.none}"
    width: "100%"
    height: "1px"
  skip-link:
    backgroundColor: "{colors.field}"
    textColor: "{colors.ground}"
    rounded: "{rounded.none}"
    padding: "0.8rem 1.2rem"
---

# Design System: QI-Fingerprint — The Core Log

## Overview

**Creative North Star: "The Core Log"**

The page is a cored section through an ECDSA signature corpus, read top to bottom as a
descent. The physical scene decides everything: split drill core laid in a tray under flat
shed light. The tray is dark and slightly green — wet slate, not black — and the core laid
in it is pale. So the page ground is the tray, every reading surface is pale stock laid on
top of it, and figure and ground are literal: data sits on paper, prose sits on the tray.

Density is high and the chrome is thin. There are no card shells, no gradients, no glass,
no glow and no shadows anywhere in the shipped build; depth is stated by ruling, hatch and
position. Every mark is a measurement — hatch encodes class, width encodes value, position
encodes depth — and the one authored motion moment is readings arriving as the reader passes
their depth. The system refuses the category default it was built against: a centred claim
over a terminal transcript followed by a row of feature cards.

The build's rarest commitment is arithmetic. The assay colour appears exactly once on the
page — verified by pixel-sampling both full-page captures, where it occurs as a single 1px
rule and nowhere else — and every class carries a hatch as well as a hue, so the sheet
survives a photocopier and a reader who cannot separate green from amber.

**Key Characteristics:**
- Two grounds only: the dark tray for prose, pale stock for logged results.
- One committed ink weight: 1px rules across the whole drawing system.
- Square corners everywhere; radius is not part of the vocabulary.
- Hatch carries class identity; hue is the fast read, never the only read.
- One accent, used once, on the one recovered key.
- One motion clock, resolved by default in the server-rendered markup.
- One navigation axis: the depth rail, and nothing else.

## Colors

A wet-slate tray, pale log stock, one blue field ink for annotation, and a single warm
assay that is a finding rather than a decoration.

### Primary
- **Field Ink** (`{colors.field}`): annotation on the tray — repro commands, the depth
  cursor and its active tick, recovered-key flags, selection, caret and focus ring. It marks
  what the survey added to the rock.
- **Field Ink Deep** (`{colors.field-deep}`): the same annotation role when it lands on pale
  stock — assay numerals, repro commands and selection inside `.sheet`.

### Secondary
- **Assay** (`{colors.assay}`): the one recovered key. It appears exactly once, as the
  full-width 1px rule at the head of the assay interval (desktop capture row 13513,
  x 160–1391; mobile row 21561, x 24–365). Nothing else on the page may use it.

### Tertiary
Lithology hues, one per diagnosis class, each paired with a hatch pattern in `HatchDefs`:
- **Truncated MSB** (`{colors.truncated-msb}`) — hatch ruled hard right.
- **Modular Reduction** (`{colors.modular-reduction}`) — cross hatch, folded back on itself.
- **Short-Period PRNG** (`{colors.short-period-prng}`) — repeating dot pool.
- **Weak Seed** (`{colors.weak-seed}`) — short dashed seam.
- **Clean Host Rock** (`{colors.clean}`) — sparse dot, effectively unmarked.

### Neutral
- **Wet Slate** (`{colors.ground}`): the tray; page background and the ground of all prose.
- **Raised Tray** (`{colors.ground-raised}`): figure panels and unattributed laminae — a
  tonal step, never a lifted card.
- **Tray Rule** (`{colors.rule}`) and **Tray Rule Strong** (`{colors.rule-strong}`): the 1px
  ruling that separates intervals and rows on the tray; the strong value carries scale ticks,
  scrollbar thumb and emphasis rules.
- **Log Stock** (`{colors.stock}`) and **Stock Rule** (`{colors.stock-rule}`): the pale sheet
  that logged results sit on, and its ruling.
- **Stock Ink** (`{colors.stock-ink}`): type on stock; transparency mixes (`/80`, `/65`,
  `/55`) carry its secondary and label ranks.
- **Ink / Ink-2 / Ink-3** (`{colors.ink}`, `{colors.ink-2}`, `{colors.ink-3}`): the three
  ranks of type on the tray — primary reading, running prose, and captions/labels.

### Named Rules
**The Single Assay Rule.** The assay colour is used exactly once per page, on the one real
recovered key. It is not an accent; it is a finding. Audit test: sample every pixel of a
full-page capture; there must be exactly one contiguous run of it.

**The Hatch-Before-Hue Rule.** No class is ever encoded by colour alone. Every lithology ships
a hatch pattern and a hue together, and the chip travels with the label into running text and
table cells, not only into the legend.

**The One Vocabulary Rule.** Drawn marks take the same tokens as typeset ones, by job rather
than by medium: structural lines and population edges in tray rule strong, gridlines in tray
rule, annotation text inside a figure in ink-3, ordinary data marks in clean host rock, and
knockouts against a figure panel in raised tray. An SVG never invents its own colour names.

**The Two-Ground Rule.** Prose sits on the tray; logged results sit on stock. A block chooses
one ground and stays on it — `.sheet` swaps ink, rules, selection and repro colour together,
never colour by colour.

## Typography

**Display Font:** Archivo (with ui-sans-serif, system-ui fallback), self-hosted via next/font.
**Body Font:** Archivo — the same grotesque carries headings and prose.
**Label/Mono Font:** Spline Sans Mono (with ui-monospace, SFMono-Regular, Menlo fallback).

**Character:** Archivo is a grotesque drawn for print set small and read fast under bad
light — charts, signage, forms. Spline Sans Mono shares its skeleton, so a reading dropped
into a sentence sits on the same baseline logic as the words around it. Tabular figures
(`tnum`, `zero`) are on for every reading, so a column of numbers aligns to the millimetre.
`font-synthesis-weight: none`: only real weights ship.

### Hierarchy
- **Display** (700, `clamp(2rem, 4.2vw, 3.6rem)`, 1.02, -0.04em): the assay heading only —
  the one full-viewport beat.
- **Headline** (700, `clamp(1.85rem, 3.4vw, 3rem)`, 1.02, -0.035em): interval headings, set
  against the tray in a 12-column header with the standfirst at column 8.
- **Title** (600, 1rem–1.25rem, 1.3, -0.02em): row and lane headings inside an interval.
- **Body** (400, 0.92rem–1.05rem, 1.7–1.75): running prose, capped at 52–74ch depending on
  column; the standfirst runs to 62ch.
- **Reading** (400, 0.68rem–0.82rem, tabular, -0.01em): every measured value, plus repro
  commands. 256-bit values use the same face with `word-break: break-all`, line-height 1.7
  and `user-select: all`, so a key wraps inside its column and copies whole.
- **Label** (500, 0.6rem–0.7rem, 0.12em–0.2em tracking): column heads, field names in the
  title block, rail tick labels, figure captions inside SVG.

### Named Rules
**The Readings-Only Mono Rule.** Mono sets measured values and commands, never prose. The
title block's `finding` row is set in the display face at 700 precisely because it is a
sentence, not a reading. If a mono string reads as a sentence, it is in the wrong face.

**The Balanced Head Rule.** Headings use `text-balance` and stay short enough for one or two
lines; the standfirst beside them carries the sentence that says what the interval establishes.

## Layout

One continuous section, never a stack of panels. Intervals are full-bleed sections separated
by a single top rule, padded `1.5rem` at the gutter, `3rem` from `md`, and inset `10rem` on
the left from `lg` to clear the depth rail. Vertical rhythm is `5rem` per interval, `7rem`
from `md`; logged rows are `1.75rem`. Content is centred in a `1500px` maximum measure and
laid on a 12-column grid from `md` — headings at columns 1–6, standfirsts at 8–12, figures
and tables taking 4/7/8-column splits. The collar and the assay interval each take a full
`100svh`; nothing else does.

Breakpoints are Tailwind defaults (`md` 768px, `lg` 1024px) plus a `max-width: 767px` rule
that turns every `.stack-table` into one block per row, each cell carrying its column name
from `data-label` and the header row visually hidden. Wide tables are not scrolled sideways
on a phone; they restack, because the markup stays a real table and only the presentation
changes. Log stock carries a real 27px/28px repeating rule, at the same rhythm as the type.

### Named Rules
**The Single Axis Rule.** The depth rail is the only navigation. There is no menu, no tab bar
and no second way through; you move by descending. The rail is a scale, not a progress bar —
its ticks are the logged intervals, positioned by their true extent. It is `lg`-only and fades
in after 0.65 viewports of descent; below `lg` the descent itself is the navigation.

**The Nothing-Dropped Rule.** Narrow viewports re-arrange; they never drop a column, truncate
a command or hide content behind a horizontal gesture. A command wraps (`pre-wrap`,
`overflow-wrap: anywhere`) rather than running off the sheet with its tail unreachable.

## Elevation & Depth

There are no shadows in this system — not one `box-shadow` ships. Depth is a reading, not a
lighting effect: it is carried by ruling, by tonal steps between the tray, the raised tray and
pale stock, and by position on the depth axis. Hovering a logged row raises a 9–10% field-ink
tint within the row rather than floating it. A static grain at 0.035 opacity in `overlay`
blend sits over the whole page as the tray's own surface, never as atmosphere.

### Named Rules
**The Flat Sheet Rule.** No shadow, no glow, no blur, no gradient, no glass. If an element
needs to separate from its surroundings, it gets a 1px rule or a different ground.

## Shapes

Every corner is square: `border-radius: 0` is asserted explicitly on the focus ring and the
scrollbar thumb, and no component in the build carries a radius. The single exception is the
round legend dot in the cohort legend, which is a datum marker matching the circular nodes in
the figure, not a chrome shape.

The form language is ruled rectangles: intervals separated by top rules, tables ruled by row,
title-block fields ruled top and bottom, figures framed by a 1px border on the raised tray.
Laminae in the core tray are 11px bars with a 3px gap, width proportional to signature count,
filled with their hatch and stroked in their lithology hue; unattributed laminae are raised
tray fill with a strong-rule stroke, drawn as blank host rock rather than omitted.

### Named Rules
**The One Committed Ink Weight Rule.** 1px rules, always, everywhere — section dividers, table
rules, figure strokes, the assay mark, the depth rail. A log that hedges between hairlines and
heavy borders reads as a web page wearing a log's clothes. Emphasis comes from colour and
length, never from thickness.

## Components

### Intervals
- **Shape:** full-bleed section, square, separated by a single top rule (`{colors.rule}`).
- **Header:** heading and standfirst on a 12-column grid; no kicker, no section number, no
  eyebrow — the depth rail already says where you are.
- **Depth:** each section carries `data-interval` with what was logged there; the rail reads it.

### The Log Sheet
- **Background:** pale stock with real 27/28px ruling (`.ruled`) when readings sit directly on it.
- **Ink:** stock ink, with `/80`, `/65` and `/55` mixes for secondary and label ranks.
- **Border:** stock rule at 1px; no radius, no shadow, no padding shell beyond `1.75rem`.
- **Selection:** `.on-stock` swaps selection to deep field ink on stock.

### Tables
- **Column heads:** mono, 0.65rem, 0.16em tracking, ink-3 (or 55% stock ink on stock).
- **Rows:** 1px bottom rule; hover raises a 9% field tint (10% deep field on stock).
- **Narrow:** `.stack-table` restacks each row as a block with `data-label` prefixes at 6.5rem.

### Repro Command
- **Style:** mono reading, 0.76–0.8rem, field ink on the tray and deep field on stock,
  preceded by a 1px top rule and `1rem` of space. Selectable whole; never truncated.

### Lithology Chip
- **Style:** a 14px SVG square, filled with the class hatch and stroked 1px in the class hue,
  set inline with the label wherever a class is named.

### Depth Rail
- **Style:** a 1px full-height scale at 3.25rem from the left with a field-ink fill scaled to
  scroll fraction; ticks are 1px marks, 0.5rem wide at rest in strong rule, 1.5rem wide in
  field ink when active, with a mono 0.62rem label that appears on hover or when current.
- **States:** hidden and `aria-hidden` until 0.65 viewports of descent, then fades in over
  500ms; `lg` and up only. A 2-digit depth percentage sits at the bottom left.

### The Assay Beat
- **Style:** a full-viewport (`100svh`) interval opening with the page's only assay-coloured
  element — a 1px full-width rule that strikes in once (`assay-strike`, 1150ms) and stays.
  Beneath it, the recovered key's fields are set as ruled reading rows with `break-all`.

### The Core Tray
- **Style:** the corpus drawn as laminae across two runs, with a dashed scale line and
  end-of-scale readings in mono at 7–9 SVG units.
- **The beat:** on mount, and only when motion is wanted, every lamina is dropped to `--in: 0`
  with `transition-property` suppressed (the shorthand would wipe the per-bar delay that is the
  stagger), the reset is forced to land, and the bars are released a frame later on the 9ms-per-bar
  delay the markup already carries. The tray cuts in bar by bar from the collar edge over 520ms;
  recovered-key ticks ride the same clock at delay + 200ms, so the flag goes in after the core is
  laid rather than hanging in empty space. Measured across the beat: minimum scale 0, settling with
  all 76 elements at 1; under reduced motion the minimum ever seen is 1.
- **Pointer:** the pointer is the only control. Hovering or tapping a lamina writes key, signature
  count, class and recovered state into one `aria-live` readout. `touch-action` is suppressed only
  from `md` up (`touch-auto md:touch-none`), because at phone width the figure is 400px of the
  first screen and taking the touch action there meant a drag over it scrolled nothing.
  `pointerdown` sets the reading (a tap fires no `pointermove`), `pointerleave` is ignored for
  touch pointers (it fires the instant the finger lifts, which set and wiped the reading in one
  gesture), and the caption reads "tap a section to read a key" below `md`, "point at the section"
  above it.

### The Cohort Figure
- **Style:** two authored compositions, both rendered, one hidden per breakpoint. The wide
  composition uses a 1000×470 viewBox with precomputed node positions (no force simulation);
  the compact one uses a 320-unit viewBox so one user unit is about one device pixel at phone
  width and 10 units of type renders as 10px. Every node and edge is drawn twice — grey
  population layer, diagnosis-coloured layer above it — and the scrubber animates only the
  upper layer's opacity, so the server-rendered markup is already the resolved end state.

### Motion
- **Clock:** one custom property, `--in`, written per element by the descent controller — and,
  for the collar tray alone, by the tray's own mount effect — and read by every animated property. Easing is `cubic-bezier(0.16, 0.84, 0.28, 1)` throughout;
  durations 520ms (lamina), 620–760ms (readings, cascade, derivation), 900ms (track draw),
  1150ms (the assay strike). Scroll is weighted by Lenis at 1.1s; touch keeps native physics.
- **Grammar:** a reading is wiped in from its leading edge by a mask, never translated and
  never faded up in place; a track draws itself along its own length; the assay mark strikes
  once and does not loop.

### Named Rules
**The Resolved-By-Default Rule.** `--in` initialises to 1, so the server-rendered sheet is
already finished. The controller sets it to 0 only for elements it can prove are below the
fold, and only once it knows JS is running and motion is wanted; the collar's tray effect is the
only other thing permitted to set it to 0, under the same conditions. No-JS and reduced motion get
every reading immediately — the preference removes the animation, it never substitutes a
lesser one and never hides content.

**The One Clock Rule.** There is one authored motion moment: readings arriving as the reader
passes their depth. No section has an entrance of its own. Anything that animates must be a
reading arriving.

## Do's and Don'ts

### Do:
- **Do** pair every class hue with its hatch pattern, and carry the chip into running text and
  table cells rather than leaving it in the legend.
- **Do** draw every rule, stroke and divider at 1px.
- **Do** keep corners square (`{rounded.none}`) on every surface.
- **Do** choose one ground per block — tray for prose, stock for logged results — and swap
  ink, rules and repro colour together with it.
- **Do** set measured values in Spline Sans Mono with tabular figures, and prose in Archivo.
- **Do** ship every animated element in its resolved state in the markup, and animate only
  below-fold elements through `--in`.
- **Do** give narrow viewports their own arrangement when scaling would make type unreadable —
  a second authored composition, not a shrunk first one.
- **Do** restack wide tables below 768px with `data-label` on every cell.
- **Do** attach a repro command to every claim, set as a selectable, wrapping line.
- **Do** draw SVG marks from the same tokens as typeset ones — rule-strong for structural
  lines, rule for gridlines, ink-3 for annotation text, clean for ordinary data marks,
  ground-raised for knockouts.

### Don't:
- **Don't** use the assay colour anywhere but the single recovered-key mark. A second use
  deletes the first one's meaning.
- **Don't** encode a class, state or category by hue alone.
- **Don't** set prose in the mono face, or use mono as a costume for "technical".
- **Don't** add a shadow, gradient, glass, blur or glow; the system has none and depth is
  carried by ruling, ground and position.
- **Don't** wrap content in a card shell with a radius.
- **Don't** add a second navigation — no menu, no tab bar, no in-page index competing with the
  depth rail.
- **Don't** give a section its own entrance animation, or translate an element into place under
  a reader mid-read.
- **Don't** put a kicker, eyebrow or section number above a heading.
- **Don't** hide content behind a horizontal gesture on a phone, or truncate a command.
- **Don't** leave browser surfaces — selection, caret, scrollbar, focus ring — at their defaults.

## Unresolved

- Section order may still be re-cut; nothing may be lost. The order shipped in `RunPage`
  (collar, seam, method, triage, cohort, cascade, assay, assays, lost core, prior surveys,
  title block) is the current build, not a pinned rule.
- Deploy target is settled: GitHub Pages at https://cyrus-fr.github.io/QI-Fingerprint/,
  built in CI by `.github/workflows/pages.yml`. The export is not committed. Because a
  project page serves from `/<repo>` rather than the domain root, `next.config.mjs`
  reads `PAGES_BASE_PATH`, which CI sets from the repository name; local builds and
  `next dev` leave it empty and stay at the root.
