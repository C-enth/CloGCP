# CloGCP 001: independent correction distribution and read-only history

Accepted for the user-authorized CloGCP correction task. No new framework, database
schema, methodology mapping, collector, frontend or AWS evaluation is introduced.

CloGCP starts the existing application through a new entry module. It uses a separate
configuration directory and default workspace. A marker check runs before launcher,
Store and workspace-open writes when the CloGCP profile is active. Existing unmarked
workspaces are refused; the original CloSec workspace must never be selected as the
new writable workspace. With this profile absent the existing behavior is unchanged.

GCP rules consume indexed persisted normalized observations and source completeness.
Cross-project joins require explicit collected canonical references, including Shared
VPC network identifiers. No new attack-path kind or inferred relationship is created.
New criteria have no invented methodology mappings. Confidence, severity, criterion
outcome and approval remain independent.

Historical reconciliation reads a closed database with DuckDB read_only=True and
performs no recovery, migration or Store initialization. Its versioned JSON preserves
IDs and review records. Comparison never applies an approval. Changed evidence,
semantics or severity require revalidation; an absent current finding is not proof
of remediation. History is optional and the new engine does not depend on it.

The additional assurance workbook and JSON expose implemented criteria, review-only
criteria, context consumers and unsupported families. The existing assessment export
and forty-column GCP register remain available. No GUI changes are needed.

A separate portable source release reuses the validated offline dependencies and
compiled frontend. Native Windows execution and desktop Excel remain explicit
platform gates; macOS checks cannot establish Windows acceptance.
