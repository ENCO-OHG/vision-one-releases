# Maintaining Vision One Product Security

This directory contains public website configuration, styles and assessed advisory data. Do not commit private vulnerability reports, exploit evidence, credentials or customer data here. The site is English-only and does not change installer publication.

## Publication

1. Assess product applicability and affected versions privately. A dependency advisory is not automatically a Vision One vulnerability. Coordinate disclosure before adding public material.
2. Add an assessed entry to `advisories.json` using the schema below. Publish only supported findings, not fabricated examples. An applicability notice may retain an open assessment if its evidence and uncertainties are explicit.
3. Use a stable ID such as `VO-SA-YYYY-NNN`. IDs are never reused. Publication and revision timestamps use UTC, for example `2026-10-20T09:00:00Z`.
4. For a revision, retain the ID and original `published` timestamp, update `updated`, and explain material changes in the advisory text. Keep resolved advisories available instead of silently removing them. The stable Atom entry ID and changed revision timestamp allow feed readers to identify updates; individual notification behavior depends on the reader.
5. Run `npm test` and `npm run build`. Review affected/fixed versions, links, severity, recommended actions, public wording and generated HTML/Atom before approving the change.
6. Commit and push the reviewed change to `main` when publication is authorized. The Pages workflow tests and builds before deploying. It does not create a software release, touch an installer or publish a CVE.

The `reviewed` value in `site.json` records the initial archive review, not a continuously refreshed vulnerability assessment. Build timestamps do not manufacture advisory updates. The feed is usable while empty and must not be represented as evidence that no vulnerabilities exist. This site does not provide email subscriptions, CSAF distribution or an automatic connection to GitHub Security Advisories.

## Advisory schema

Required fields:

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier matching `VO-SA-YYYY-NNN` (at least three sequence digits). |
| `title`, `summary` | Public title and concise product-specific summary. |
| `published`, `updated` | Full UTC timestamps; revision cannot predate publication. |
| `severity` | `critical`, `high`, `medium`, `low`, `informational` or `not-rated`. Use `not-rated` when no severity assessment has been established, rather than inventing a rating. |
| `status` | `open`, `mitigated` or `resolved`. Resolution does not remove the advisory. |
| `affected` | Nonempty array of product/version/action records, described below. |
| `impact`, `remediation` | Assessed impact and concrete customer action in plain text. |
| `workarounds` | Array of assessed mitigation strings, or `[]`. |
| `references` | Array of `{ "title": "...", "url": "https://..." }`, or `[]`. |
| `cves` | Assigned CVE IDs only, or `[]` when none is assigned. |

Each `affected` entry contains `product`, an explicit human-readable affected `versions` range, `fixedVersions` (an array, empty if no fixed version is available), and `action` (recommended action for that product/range). Version ranges are displayed as assessed text; the website does not infer applicability or perform SemVer comparisons.

Optional `cvss` is a numerical score between 0 and 10. When supplied, identify the CVSS version/vector and scoring rationale in the impact text or an authoritative reference. Do not invent a CVE or score. Review any affected-version interpretation and remediation guidance before publication.

Optional `severitySource` is `product` (the default) or `upstream`. Use `upstream` when reproducing a dependency advisory's rating without a separately established product rating; the archive, detail page and Atom category label explicitly identify that source. Any numerical CVSS score displayed for such an entry is also labelled upstream. Explain the source, version/vector and distinction in the impact text. Optional `assessment` is a nonempty array of plain-text paragraphs for the evidence, review scope, limitations and current product-applicability conclusion. An upstream score and an included dependency do not, on their own, establish product exploitability.

Optional `reviewedVersions` is a nonempty array of distinct version labels. It displays a compact **Reviewed versions** line below the advisory title on the home page and in the archive. Populate it from the actual review scope, not by inferring ranges from prose. It does not declare confirmed product exploitability or imply that unlisted versions are unaffected; the full `affected` and `assessment` text remains authoritative. Adding this presentation metadata without changing the assessment does not, by itself, require a new technical revision timestamp.

All strings are rendered as text, not Markdown or HTML. Only HTTPS reference URLs without embedded credentials are accepted. Per-advisory pages and the Atom feed are generated from this single source to avoid divergent copies.

## Deployment and privacy

### Maintaining the review snapshot

`status.json` provides the dated review snapshot at `/security-status/`. It records the reviewed product version and scoped npm audit package-entry counts. The page derives its open-notice list from the advisory records; it does not treat a dependency count as a product exploit count. `/deployment/` provides baseline operating guidance and is not an exhaustive security checklist.

For each product release, recheck the open notices against that release's manifests and relevant source paths. Run the documented audits for the reviewed checkout before updating `reviewedAt`, `productVersion` or counts. Keep build-tool findings distinct from production npm findings, explain duplicated dependency-chain entries, and record the limits of native-component and application-code coverage. Do not advance the review date automatically during a website build. A website content change does not alter a previously attached release audit or close an advisory.

If a review changes an advisory's scope, impact or remedy, retain its ID and original publication date, update its revision timestamp, and document the material revision. The Atom feed then exposes the revised entry. Updating a product version alone never establishes that an open finding has been fixed. Do not upload raw audit evidence containing private paths, credentials or customer data.

### Hosting

Pages must be configured to use **GitHub Actions**. Pushes to `main` and manual workflow dispatches deploy after tests; pull requests build but cannot deploy. The workflow only needs content-read access for the build and Pages/OIDC permissions for deployment. Deployment is serialized.

The static site uses system fonts, local assets, no analytics, no JavaScript, no email form and no mailing-list database. Visitors can use the public Atom feed without a GitHub account. GitHub hosting remains subject to GitHub's privacy practices. The security email is a confidential reporting contact, not an end-to-end encrypted submission service; no PGP key or response-time guarantee is advertised.
