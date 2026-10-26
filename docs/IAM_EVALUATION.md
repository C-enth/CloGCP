# IAM evaluation — R1.2

Sprint 3 enterprise snapshots reuse this evaluator across independently collected accounts,
separately per AWS partition. Observed trust and evaluated authorization are different edges;
missing dependencies cap support and applicable deny origins remain explicit blockers.
Supported permission is not verified attacker control or confirmed escalation. S3/KMS policy,
grant and workload/network relationships are configuration references, not a new effective
service-access evaluator. See [enterprise usage](ENTERPRISE_USAGE.md) for exact qualifications.
AWS documents the separate cross-account permission sides in
[IAM cross-account access](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html)
and service-specific dependencies in
[KMS cross-account key use](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-modifying-external-accounts.html).

Implemented offline in `iam/`, with structural adapters in
`normalization/iam_adapters.py`. These are bounded analyzer conclusions from exported
configuration, not live AWS authorization answers. Real-export compatibility remains
unverified. All inputs in the golden suite are synthetic.

## Decision contract

| State | Meaning |
|---|---|
| ALLOWED_WITH_SUPPORTED_CONTEXT | Every evaluated authorization layer allows the modeled request with supported context |
| DENIED_BY_EVIDENCE | A matching explicit deny or a resolved layer without a matching allow blocks the request |
| POTENTIALLY_ALLOWED | A grant is plausible but required context or policy evidence is incomplete |
| UNKNOWN | Required identity evidence or statement semantics cannot be resolved |

Missing SCP evidence caps a supported identity grant at POTENTIALLY_ALLOWED. Missing
policy documents, boundaries, conflicting snapshots and truncated listings are retained
as gaps; attachments never substitute for policy documents. Matching denies override
allows. Confidence, rule outcome, finding class, technical severity and analyst status
are independent. No decision confirms exploitation.

## Supported subset

Action/NotAction and Resource/NotResource support `*` and `?` matching (actions ignore
case; resources preserve case). Identity policies intersect with permissions boundaries
and applicable SCPs. SCPs evaluate inherited root, OU and account attachments; policies
at a level are combined and levels intersect. RCPs constrain cross-account target access.
Management accounts, service-linked roles, disabled SCP policy types and evidenced
accounts outside an organization are exempt from SCPs.

Condition operators: StringEquals, StringNotEquals, StringEqualsIgnoreCase,
StringNotEqualsIgnoreCase, StringLike, StringNotLike, ArnEquals, ArnLike, ArnNotEquals,
ArnNotLike, Bool and Null. Supported IfExists variants distinguish a key known absent
from a key whose value was not collected; unknown context remains unresolved. Positive
string alternatives use OR, negated alternatives use NOR, and distinct conditions use
AND. Multivalued string context requires unsupported set semantics and stays unresolved.

Trust matching supports wildcard, exact role ARN, account ID and account-root principals.
Cross-account AssumeRole requires source identity authorization, target trust and target
RCPs. Context includes evidenced principal ARN/account, resource account, service status
and organization membership; MFA and external session context are not invented.

PassRole investigations cover EC2 RunInstances and Lambda CreateFunction/InvokeFunction,
service trust, source PassRole permission, target and source privilege, and EC2 instance
profile membership (or permissions to create and populate a profile). Service operations
with multiple resource types require literal Resource `*`; narrower grants are unresolved.
Observed relationships remain distinct from evaluated permission relationships.

## Unsupported and excluded semantics

Numeric, date, IP and binary condition operators, ForAnyValue/ForAllValues set operators,
policy variables, malformed statements and unrecognized statement elements never yield
a supported Allow. NotPrincipal, assumed-role session principals and unique principal
IDs remain unresolved in trust evaluation. RCP principal matching supports only `*`.
Generic same-account resource-policy authorization (including S3/KMS policies),
same-account AssumeRole and session-policy evaluation are excluded. Session-policy
omission is recorded on decisions; this models principal capability without optional
session restrictions, not the permissions of a particular live session.

Investigations are bounded candidates, not an exhaustive AWS action catalog or general
attack graph. Attacker control, SSRF/RCE, credential retrieval and execution remain
manual prerequisites. AP-04/AP-06 records never become SUPPORTED from this evidence.

## Evidence and local verification

Eight per-role/policy/profile IAM operations and ten Organizations operations are listed
in EVIDENCE_SCHEMA.md. AWS-managed documents and URL-encoded documents are supported.
Collector packages must record subject request parameters, collection scope, timestamps,
errors and pagination. The local verifier reports fixed field names and counts only;
field presence is structural diagnostics, not proof of semantic completeness.

Run on the assessment VM with actual collector files, keeping results local and ignored:
```sh
.venv/bin/python -m offline_analyzer.verification --package <collector-package> \
  --origin tool-generated --output artifacts/r12-real-verification.json
```
Do not label synthetic runs as tool-generated. Output requires explicit authorization
before sharing. Windows execution and real collector shapes remain unvalidated.
