# Brand

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

| | |
| :--- | :--- |
| Status | Name and mark: accepted and implemented ([ADR 0013](adr/0013-the-product-is-called-river.md)). Tagline: accepted (2026-11-25, repository owner), used in the README. "Spoilers": proposed, not implemented. |
| Verified | 2026-11-25: the logo files and their use in the frontend. The rest is agent-written and not reviewed. |

## Name

The brand has three parts: a recursive acronym, a tagline and a story.

**River**: *River Inspects Vulnerabilities and Evaluates Risks.* The "and" does not
count towards the acronym.

Write it "River", capitalised, no article. On first mention in a document, add what it is:
"River, the review tool for Dependency-Track findings". The word alone is too common to
search for.

River was called DTVP before. Identifiers still carry that name;
[ADR 0013](adr/0013-the-product-is-called-river.md) lists which.

## Tagline

> ≋ River: read the ripples before they reach the shore.

In running text, without the mark: "Read the ripples before they reach the shore."

## Story

River is named after River Song from *Doctor Who*, who was born Melody Pond. Every new
vulnerability lands like a drop in a pond: the ripples spread outward through every
product and release that contains the affected component. River follows those ripples,
so teams can assess each finding once and carry the decision across versions.

The name is a nod, not a licence. Do not use the character's full name, likeness, quotes
from the series or BBC artwork in the product, the logo or the documentation.

## Mark

The mark is the triple tilde: three waves, nothing else.

| Use | File |
| :--- | :--- |
| Icon, favicon, login screen (24 × 24) | [`data/river-mark.svg`](../data/river-mark.svg) |
| README header (159 × 78, shown at twice that width) | [`data/river-wordmark.svg`](../data/river-wordmark.svg) |

- Typeface: Share Tech Regular (SIL Open Font License 1.1, Copyright 2012 The Share Tech
  Project Authors). Share Tech has no ≋ glyph, so the three waves are its tilde `~`, stacked.
- The wordmark is the waves directly followed by the lowercase word "river", with no
  space. The waves are centred on the x-height of the word. The acronym runs in one
  line underneath, exactly as wide as waves and word together, with its initials in
  the colour of the waves. It is small: show the wordmark at 300 px or wider.
- Both files hold outlines, not text, so they look the same without the font installed.
- Colour: waves `#378ADD`, word `#6B7F88`. The waves' contrast is 3.6:1 on white and
  5.0:1 on the app background `#121820`, so one file serves light and dark surfaces.
- The frontend reads the icon through `frontend/src/lib/brand.ts`; the Docker builds copy
  it by file name.

As a character the mark is **≋** (U+224B, TRIPLE TILDE), for wherever an image cannot go:
terminal banners, page titles, headings. Write it before the name with one space,
`≋ River`. Do not use it as the only label of a control; screen readers announce it as
"triple tilde".

## Spoilers

Proposed, not implemented. "Spoilers" is meant as the product's one in-joke: the label of
the hint shown when the finding in view has already been assessed in a later version.

| Element | Text |
| :--- | :--- |
| Badge | Spoilers |
| Tooltip | Already assessed in version {version}. Open that assessment. |

- One place only.
- The tooltip carries the meaning; the badge must never be the only explanation.

Open: which element this is. No existing element means exactly "a later version already
has an assessment".

## Voice

Plain and specific. The water images (ripples, current, flow) belong to the tagline, the
README introduction and release notes. Screens, errors and documentation of behaviour
keep the existing vocabulary: finding, assessment, team, reviewer, lifecycle.
