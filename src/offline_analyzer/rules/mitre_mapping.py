"""Curated MITRE ATT&CK for Cloud mapping of CloSec rules (versioned, reviewed entries only).

Every entry names one technique whose IaaS behaviour the observed configuration enables or
matches, the tactic as published, a rationale tied to the observed configuration (`{resource}`
is filled from the finding), and the technique reference. Technique IDs, names, tactics and
platforms were checked against the ATT&CK Enterprise technique pages (content v20.0) on
2026-10-22; v20 moved "Disable or Modify Cloud Logs" from T1562.008 to T1685.002 (tactic
Defense Impairment). Status ENGINEERING_REVIEWED means checked by CloSec engineering; analyst
approval of the mapping is pending and is stated wherever the mapping is shown.

A rule without an entry is "not mapped": no technique is guessed. A mapping describes the
technique an adversary could use against the observed configuration; it never claims the
technique was used. STRIDE is a separate mapping (methodology links) and is not derived here.
"""

from dataclasses import dataclass

ATTACK_VERSION = "ATT&CK Enterprise v20.0"
REVIEWED_ON = "2026-10-22"
STATUS = "ENGINEERING_REVIEWED"
MAPPING_VERSION = "mitre-mapping-1"
NOT_MAPPED = "not mapped"
NOT_MAPPED_REASON = (
    "No reviewed MITRE ATT&CK mapping exists for this rule; no technique is assigned."
)


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str
    url: str


METADATA = Technique(
    "T1552.005",
    "Unsecured Credentials: Cloud Instance Metadata API",
    "Credential Access (TA0006)",
    "https://attack.mitre.org/techniques/T1552/005/",
)
CLOUD_STORAGE = Technique(
    "T1530",
    "Data from Cloud Storage",
    "Collection (TA0009)",
    "https://attack.mitre.org/techniques/T1530/",
)
CLOUD_ACCOUNTS = Technique(
    "T1078.004",
    "Valid Accounts: Cloud Accounts",
    "Initial Access (TA0001), Persistence (TA0003), Privilege Escalation (TA0004), "
    "Stealth (TA0005)",
    "https://attack.mitre.org/techniques/T1078/004/",
)
PUBLIC_APPLICATION = Technique(
    "T1190",
    "Exploit Public-Facing Application",
    "Initial Access (TA0001)",
    "https://attack.mitre.org/techniques/T1190/",
)
CLOUD_LOGS = Technique(
    "T1685.002",
    "Disable or Modify Tools: Disable or Modify Cloud Log",
    "Defense Impairment (TA0112)",
    "https://attack.mitre.org/techniques/T1685/002/",
)

# rule_id -> (technique, rationale template). Provider is implied by the rule prefix; a shared
# rule would carry one entry used for both providers.
MAPPING: dict[str, tuple[Technique, str]] = {
    "R0-EC2-IMDSV2": (
        METADATA,
        "IMDSv1 is allowed on {resource}: code execution or SSRF on the instance can read the "
        "instance-profile credentials from the metadata API without a session token.",
    ),
    "R1-EC2-IMDS-HOP-LIMIT": (
        METADATA,
        "The metadata response hop limit on {resource} lets containers or forwarded traffic "
        "reach the metadata API and its instance-profile credentials.",
    ),
    "GCP-VM-DEFAULT-SA": (
        METADATA,
        "{resource} runs as the default compute service account; its access token is served by "
        "the metadata server to any code running on the VM.",
    ),
    "GCP-VM-FULL-API-SCOPE": (
        METADATA,
        "{resource} has the full cloud-platform access scope; a token read from the metadata "
        "server is limited only by the service account's IAM roles.",
    ),
    "R1-S3-BUCKET-PUBLIC-ACCESS": (
        CLOUD_STORAGE,
        "Bucket policy or ACL of {resource} allows public access that block public access does "
        "not stop: objects can be read without credentials.",
    ),
    "R1-S3-ACCOUNT-BPA": (
        CLOUD_STORAGE,
        "Account-level S3 block public access is not fully enabled for {resource}: a bucket "
        "policy or ACL can make objects publicly readable.",
    ),
    "GCP-STORAGE-PUBLIC": (
        CLOUD_STORAGE,
        "{resource} grants access to allUsers or allAuthenticatedUsers: objects can be read "
        "without project credentials.",
    ),
    "GCP-STORAGE-PAP": (
        CLOUD_STORAGE,
        "Public access prevention is not enforced on {resource}: a public binding can expose "
        "its objects.",
    ),
    "GCP-ORG-PUBLIC-DATA": (
        CLOUD_STORAGE,
        "An organization-wide search shows a public binding on data resource {resource}.",
    ),
    "R1-IAM-ROLE-TRUST-CONDITIONS": (
        CLOUD_ACCOUNTS,
        "The trust policy of {resource} lets principals of another account assume it without "
        "binding conditions: valid credentials there become valid access here.",
    ),
    "R1-IAM-INSTANCE-ROLE-PRIVILEGE": (
        CLOUD_ACCOUNTS,
        "Instance role {resource} carries administrator-equivalent or PassRole permissions: "
        "credentials taken from the workload act with that privilege.",
    ),
    "SEC-IAM-ROLE-WILDCARD": (
        CLOUD_ACCOUNTS,
        "Role {resource} allows Action '*': anyone able to assume it holds unrestricted "
        "permissions in the account.",
    ),
    "GCP-IAM-BASIC": (
        CLOUD_ACCOUNTS,
        "A basic role (Owner/Editor) on {resource} gives the bound principal broad permissions; "
        "its credentials grant that access.",
    ),
    "GCP-IAM-IMPERSONATION": (
        CLOUD_ACCOUNTS,
        "A principal can impersonate service account {resource} and act with its roles.",
    ),
    "GCP-IAM-CROSSPROJECT": (
        CLOUD_ACCOUNTS,
        "A service account from another project holds Owner or Editor on {resource}: its "
        "credentials are valid privileged access here.",
    ),
    "GCP-KEY-PERSISTENT": (
        CLOUD_ACCOUNTS,
        "User-managed key {resource} is a long-lived credential: whoever holds it "
        "authenticates as the service account.",
    ),
    "GCP-KEY-AGE": (
        CLOUD_ACCOUNTS,
        "Key {resource} exceeds the rotation age: a copied key stays valid longer.",
    ),
    "GCP-KEY-PRIVILEGED": (
        CLOUD_ACCOUNTS,
        "Key {resource} belongs to a service account with Owner or Editor: the key grants "
        "that privilege to its holder.",
    ),
    "GCP-ORG-BASIC-ROLE": (
        CLOUD_ACCOUNTS,
        "An organization or folder basic-role binding on {resource} grants broad inherited "
        "permissions to the principal's credentials.",
    ),
    "GCP-ORG-SA-PRIVILEGED": (
        CLOUD_ACCOUNTS,
        "Service account {resource} holds privileged roles found by the organization search.",
    ),
    "GCP-ORG-IMPERSONATION": (
        CLOUD_ACCOUNTS,
        "An organization-wide impersonation grant on {resource} lets a principal act as the "
        "service account.",
    ),
    "GCP-ORG-CROSSPROJECT-SA": (
        CLOUD_ACCOUNTS,
        "Service account {resource} is granted roles in other projects of the organization.",
    ),
    "GCP-ORG-EXTERNAL-DOMAIN": (
        CLOUD_ACCOUNTS,
        "Principals of an external email domain hold access on {resource}: credentials of "
        "those third-party accounts are valid access here (relationship to validate).",
    ),
    "GCP-ORG-FEDERATION": (
        CLOUD_ACCOUNTS,
        "External workload identities can act as a service account through {resource}: "
        "federated credentials become valid service-account access.",
    ),
    "R1-EC2-SG-SENSITIVE-INGRESS": (
        PUBLIC_APPLICATION,
        "{resource} allows 0.0.0.0/0 to a sensitive port on an in-use public interface: the "
        "listening service is reachable from the internet.",
    ),
    "R1-RDS-PUBLIC-ACCESS": (
        PUBLIC_APPLICATION,
        "Database {resource} is publicly accessible: its endpoint can be reached from the "
        "internet where security groups and routes allow.",
    ),
    "GCP-NET-FW-ADMIN-INTERNET": (
        PUBLIC_APPLICATION,
        "Firewall rule {resource} allows administration ports from 0.0.0.0/0.",
    ),
    "GCP-NET-FW-DB-INTERNET": (
        PUBLIC_APPLICATION,
        "Firewall rule {resource} allows database ports from 0.0.0.0/0.",
    ),
    "GCP-NET-FW-ANY-INTERNET": (
        PUBLIC_APPLICATION,
        "Firewall rule {resource} allows all ports from 0.0.0.0/0.",
    ),
    "GCP-SQL-OPEN-NETWORK": (
        PUBLIC_APPLICATION,
        "Cloud SQL instance {resource} authorizes 0.0.0.0/0: the database endpoint accepts "
        "connections from any address.",
    ),
    "GCP-ORG-PUBLIC-SERVERLESS": (
        PUBLIC_APPLICATION,
        "Serverless service {resource} grants the invoker role to allUsers: anyone can call it.",
    ),
    "SEC-CLOUDTRAIL-LOGGING": (
        CLOUD_LOGS,
        "Trail {resource} is not logging: the configuration matches the outcome of disabling "
        "cloud logs, so API activity is not recorded.",
    ),
    "SEC-CLOUDTRAIL-MANAGEMENT-EVENTS": (
        CLOUD_LOGS,
        "Trail {resource} does not record write management events: control-plane changes are "
        "not logged.",
    ),
    "GCP-LOG-AUDIT": (
        CLOUD_LOGS,
        "Data Access audit logging is exempted on {resource}: those accesses are not logged.",
    ),
    "GCP-LOG-EXCLUSION": (
        CLOUD_LOGS,
        "Log exclusion {resource} can drop security-relevant entries before storage "
        "(the rule flags it for review).",
    ),
}


def mitre(rule_id: str, resource: str = "") -> dict:
    """The four register cells for a rule: technique, tactic, rationale, reference."""
    entry = MAPPING.get(rule_id)
    if entry is None:
        return {
            "technique": NOT_MAPPED,
            "tactic": NOT_MAPPED,
            "rationale": NOT_MAPPED_REASON,
            "reference": NOT_MAPPED,
        }
    technique, rationale = entry
    return {
        "technique": f"{technique.technique_id} {technique.name}",
        "tactic": technique.tactic,
        "rationale": rationale.format(resource=resource or "the resource")
        + f" Mapping status: {STATUS} against {ATTACK_VERSION} on {REVIEWED_ON}; analyst "
        "approval pending. Potential technique, not observed activity.",
        "reference": technique.url,
    }
