# CloGCP development validation

All assessment inputs below are generated synthetic data. No client project package,
Batch 1 finding, customer workspace, real review or production assessment is validated.
The original source checkout and validated CloSec release remain unchanged.

## Automated checks

- Full GCP/current correction suite: **705 passed, 4 skipped**, 277.87 seconds.
  Skips are opt-in browser tests, separately exercised in Chromium. Every registered
  criterion has positive/negative/ambiguous cases in the combined matrix/domain suites;
  source parsing, inheritance, partial collection and identity edge cases have additional
  regression tests. This is criterion testing, not certification of all GCP controls.
- New complete collector-shaped two-project end-to-end test: import, enterprise analyze,
  report ZIP, forty-column workbook, actual evidence excerpts, coverage/limitations,
  input hash preservation, absent-history behavior and investigation details for every
  added criterion that generates a finding. Final history/presentation regression:
  **12 passed**, 14.80 seconds. This follow-up verifies explicit current local decisions
  are reported accurately without applying historical approvals; stale fingerprints
  require revalidation.
- Real Chromium through the CloGCP entry module: **1 passed**, 41.79 seconds. Existing
  compiled frontend imports, assesses, investigates, reviews, exports and restarts.
  No remote runtime requests are allowed by this test. Reused UI branding stays CloSec.
- AWS/application regression selection: **325 passed, 5 failed, 1 skipped**, 77.67 seconds.
  All five failures reproduce on the untouched validated package with the same tests:
  obsolete exact sheet-list expectation (Excluded Findings), conflicting-trust reference
  behavior, cross-partition reference behavior, and two PDF/frozen-PDF expectations not
  supported by that release. No AWS implementation is changed to repair these baseline
  issues. The release candidate is not an assertion of a completely green legacy suite.
- Direct baseline/corrected AWS comparison: **97 evaluations, 8 findings and 1 review
  decision identical**. All 36 Excel ZIP members match except docProps/core.xml's timestamp.
- Ruff: complete `src tests tools` check passes. Existing contract/schema code is
  preserved; strict Pydantic validation, missing-evidence/PASS guards and the new history
  schema are tested. Historical decision IDs, SRE records, report revisions and exclusions
  are retained as history and never applied as current approval.

No test failure was hidden by skipping or weakening an existing AWS expectation.
Intermediate failures and their fixes are retained in local engineering logs. A new test
initially assumed openpyxl streaming sheets had max_row and used incorrect detail field
names; its assertions were corrected to use the actual read-only workbook/detail APIs.
The existing FastAPI/Starlette test-client dependency deprecation warning remains.

## Sequential ten-project benchmark

The same ten synthetic collector-2.2.8-shaped packages were used for both engines,
with 32 VMs/project (320 total), six insecure and four secure configurations. There are
1,220 dataset records representing all 118 catalog families plus explicit effective
policy variants, and 890 normalized observations. Many families are deliberately empty;
this measures multi-project execution and does not validate every populated real export.

| Measurement | Validated baseline | CloGCP |
|---|---:|---:|
| Import seconds | 12.56 | 10.60 |
| Analyze seconds | 6.35 | 6.78 |
| Excel export seconds | 39.15 | 43.60 |
| Total seconds | 58.06 | 60.99 |
| Evaluations | 3,156 | 3,594 |
| Resource evaluations | 3,118 | 3,546 |
| Evaluated resource/subject IDs | 578 | 718 |
| Candidate findings | 1,458 | 1,614 |

There are **156 additional synthetic configuration findings**: 144 from added criteria,
12 from corrected Storage PAP/public-grant evaluation. These counts are test outcomes,
not discovered customer vulnerabilities. All 1,614 findings belong to the six deliberately
insecure projects (269 each); no finding is generated for the four secure projects.
Existing grouping yields 64 consolidated root-cause groups. Severity: 468 High,
918 Medium, 228 Low; no Critical. Current approval is not inferred from these results.

Domain totals and exact per-rule benchmark counts are supplied in BENCHMARK.json.
Runtime measurements are local runs, not a capacity guarantee. The earlier corrected
run took 65.56 seconds; the final run used a warm filesystem cache. No speedup or
production capacity guarantee is inferred from this variance. The same full
Excel report was exported; the additional assurance workbook was exercised separately
in the two-project workflow. Large customer assessments still require local operational
acceptance. No real-export compatibility claim is made from synthetic data.

## Coverage qualification

Baseline executable rules directly reference 34 catalog entries, including aliases
and review criteria. The new registry references 56: 22 additional entries. These
counts differ from the collector's unchanged 23 EVALUATED / 95 NORMALIZED labels.

The 118 catalog-entry matrix currently distinguishes 45 entries with executable named
criteria, 11 with review-only criteria, 10 used as context and 52 without implemented
automatic analysis. Aliases are not independent controls. An implemented family does
not mean every security requirement for that service is covered. Per-run coverage
records source states and actual evaluator executions, including cited context artifacts.
See CORRECTIONS.md and DATASET_RULE_MATRIX for the remaining unsupported scenarios.

## Distribution and platform gates

Portable/source archives are independently allowlisted and checksum-manifested. No
customer data, databases, historical reports, credentials, developer environments or
Git history belong in the portable ZIP. Final CRC, clean-extraction, offline setup,
packaged-module regression and launcher results are recorded separately in
RELEASE_VERIFICATION.json alongside the final ZIP and SHA-256 files.

macOS Python 3.12 is the locally exercised platform. Native Windows startup/build and
Microsoft Excel desktop rendering remain **pending**. This is a portable Python source
release candidate, not a Windows binary or a published stable release. No commit,
push or release publication is performed by this sprint.
