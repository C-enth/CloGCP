"""Versioned plain-language explanation of each rule: why flagged, misuse, impact, fix.

Attached when findings are displayed or exported, never stored with a candidate, so
adding or revising text does not change finding fingerprints or analyst decisions.
Misuse text describes what the configuration would permit if it is not intended; it is
never evidence that misuse or exploitation happened.
"""

from offline_analyzer.findings.recommendations import recommendation

VERSION = "finding-explanations-1.1.0"
MISUSE_QUALIFIER = "Potential misuse; not demonstrated by configuration evidence."

MISUSE = {
    "R0-EC2-IMDSV2": (
        "An attacker who finds a server-side request forgery (SSRF) or similar flaw in an "
        "application on this instance could request the metadata endpoint without a session "
        "token, obtain the instance role's temporary credentials and use them elsewhere."
    ),
    "R0-RDS-ENCRYPTION": (
        "Anyone who obtains the database storage, snapshots or backups (for example a copied "
        "or shared snapshot) can read the data without needing access to an encryption key."
    ),
    "R0-CLOUDTRAIL-VALIDATION": (
        "Someone with write access to the log bucket could alter or delete CloudTrail log "
        "files to hide activity, and the change could not be detected by digest validation."
    ),
    "R1-EC2-SG-SENSITIVE-INGRESS": (
        "Anyone on the internet can reach the administrative or database port (for example "
        "SSH, RDP or a database listener) and attempt password guessing or exploit a "
        "vulnerable service."
    ),
    "R1-IAM-ROLE-TRUST-CONDITIONS": (
        "Any principal in the trusted account that is allowed to assume roles, including a "
        "compromised user or workload there, could assume this role and act with its "
        "permissions in this account."
    ),
    "R1-S3-ACCOUNT-BPA": (
        "A single mistaken bucket policy or ACL change could expose a bucket to the internet, "
        "because the account-wide guardrail that would block it is not in place."
    ),
    "R1-S3-BUCKET-PUBLIC-ACCESS": (
        "Anyone on the internet, without credentials, can access objects in this bucket as the "
        "public grant allows (read, list, and possibly write or delete), exposing or "
        "tampering with its data."
    ),
    "R1-RDS-PUBLIC-ACCESS": (
        "Where network rules allow it, the database endpoint is reachable from the internet, "
        "so attackers can attempt brute-force logins or exploit database vulnerabilities."
    ),
    "R1-EC2-IMDS-HOP-LIMIT": (
        "A compromised container or process one network hop from the instance could reach the "
        "metadata service and obtain the instance role's credentials."
    ),
    "R1-IAM-INSTANCE-ROLE-PRIVILEGE": (
        "If the workload on this instance is compromised, the attacker inherits the role's "
        "broad permissions; with iam:PassRole they could attach a more privileged role to a "
        "new resource and escalate further in the account."
    ),
    "SEC-IAM-ROLE-WILDCARD": (
        "Whoever can use this role (its workload, users, or an attacker holding its "
        "credentials) can perform far more actions than its job needs, such as deleting "
        "resources, reading data or changing security settings."
    ),
    "SEC-KMS-WILDCARD-PRINCIPAL": (
        "Principals outside the intended set, potentially in other AWS accounts, could use "
        "this key to decrypt protected data or perform other key operations where their own "
        "permissions allow."
    ),
    "SEC-EC2-SG-LATENT-EXPOSURE": (
        "As soon as this group is attached to a resource with a public address, the "
        "administrative or database port becomes reachable from the internet for brute-force "
        "or exploit attempts; the attachment can happen later without review."
    ),
    "SEC-CLOUDTRAIL-LOGGING": (
        "API activity in the trail's scope is not recorded, so an attacker's actions (creating "
        "users, changing policies, copying data) would leave no audit trail for detection or "
        "investigation."
    ),
    "SEC-CLOUDTRAIL-MANAGEMENT-EVENTS": (
        "Control-plane changes such as creating access keys, editing IAM policies or disabling "
        "security services would go unrecorded by this trail, helping an attacker persist "
        "unnoticed."
    ),
    "SEC-GUARDDUTY-ENABLED": (
        "Malicious activity in this Region, such as credential misuse, crypto-mining or "
        "contact with known-malicious hosts, would not raise GuardDuty alerts, so it could "
        "continue longer before detection."
    ),
    "SEC-CONFIG-RECORDING": (
        "Unauthorized configuration changes in this Region (for example opening a security "
        "group or disabling encryption) would not be recorded or evaluated, so tampering "
        "could go unnoticed."
    ),
    "SEC-SECURITYHUB-ENABLED": (
        "Security findings and standards checks for this Region are not centralized, so "
        "misconfigurations and alerts from other services may never be seen or acted on."
    ),
    "SEC-KMS-ROTATION": (
        "If the key material is ever exposed, it keeps protecting all new data indefinitely, "
        "increasing the amount of data affected and the time it can be misused."
    ),
    "GCP-STORAGE-PUBLIC": (
        "Anyone on the internet, or any Google account, can download objects from this "
        "bucket without belonging to the organization, exposing the data it holds."
    ),
    "GCP-API-APP": (
        "If the key leaks (for example from a web page, mobile app or code repository), "
        "anyone can use it from any application or location, accessing the allowed APIs and "
        "consuming the project's quota and billing."
    ),
    "GCP-API-API": (
        "A leaked key can call any API enabled in the project, not only the one the "
        "application needs, widening data access and billing abuse."
    ),
    "GCP-API-BOTH": (
        "A leaked key can be used by anyone, from anywhere, against any API enabled in the project."
    ),
    "GCP-KEY-PERSISTENT": (
        "Service-account keys are long-lived credentials; if a key file is copied from a "
        "laptop, repository or CI system, an attacker can act as the service account from "
        "anywhere until the key is deleted."
    ),
    "GCP-KEY-AGE": (
        "The older a key, the more places it has likely been copied; a leaked old key still "
        "works and lets an attacker act as the service account."
    ),
    "GCP-KEY-PRIVILEGED": (
        "Whoever obtains this key file gains the service account's Owner or Editor level "
        "control of the project: creating resources, reading data or changing IAM."
    ),
    "GCP-IAM-BASIC": (
        "If this principal is compromised or misuses its access, it can change almost "
        "anything in scope (delete resources, read data, alter IAM), because Owner and Editor "
        "are not limited to a task."
    ),
    "GCP-IAM-PUBLIC": (
        "Anyone on the internet (allUsers) or any Google account (allAuthenticatedUsers) can "
        "use the granted role, for example to read data or modify the resource."
    ),
    "GCP-IAM-IMPERSONATION": (
        "Principals with this binding can obtain tokens for, or act as, the service accounts "
        "in scope and gain their permissions, a common privilege-escalation path."
    ),
    "GCP-IAM-CROSSPROJECT": (
        "Compromise of the service account's home project (its workloads or keys) gives the "
        "attacker Owner or Editor control of this project as well."
    ),
    "GCP-GOV-KEYS": (
        "Without the organization policy, anyone with the needed IAM permission can create or "
        "upload service-account keys, producing long-lived credentials that can leak."
    ),
    "GCP-LOG-AUDIT": (
        "Data reads and writes by the exempted principals are not logged, so data access or "
        "exfiltration by those identities, or an attacker using them, leaves no audit trail."
    ),
    "GCP-LOG-EXCLUSION": (
        "If the exclusion filter matches security-relevant events, an attacker's activity in "
        "that category would not be retained for detection or investigation."
    ),
    "GCP-SCC-OBSERVATION": (
        "Security Command Center reports an active issue on this resource; how it could be "
        "misused depends on the reported category shown in the finding evidence."
    ),
    "GCP-ORG-PUBLIC-SERVERLESS": (
        "If ingress and any frontend admit the request, a caller needs no Google identity to "
        "invoke the service; what the caller can then do depends on the application's own "
        "authorization. Invocation does not hand over the runtime identity, and the binding "
        "alone does not establish internet reachability."
    ),
    "GCP-ORG-PUBLIC-DATA": (
        "Anyone on the internet, or any Google account, can read and, depending on the role, "
        "modify the data in this resource without belonging to the organization."
    ),
    "GCP-ORG-PUBLIC-OTHER": (
        "Anyone on the internet, or any Google account, can use the granted role on this "
        "resource, with effects that depend on the role."
    ),
    "GCP-ORG-BASIC-ROLE": (
        "If this person's account is phished or compromised, the attacker gains near-full "
        "control of everything in scope: data, resources and IAM."
    ),
    "GCP-ORG-SA-PRIVILEGED": (
        "Any workload running as this service account, or anyone able to impersonate it or "
        "steal its key, can take broad control of the project; default compute service "
        "accounts are a common escalation path."
    ),
    "GCP-ORG-IMPERSONATION": (
        "The principal can impersonate every service account beneath this project, folder or "
        "organization, including privileged ones, and act with their permissions."
    ),
    "GCP-ORG-CROSSPROJECT-SA": (
        "An attacker who compromises the source project's workloads or keys can use this "
        "service account to operate in this project with its privileged role."
    ),
    "GCP-ORG-DELETED-PRINCIPAL": (
        "If the deleted principal is restored within the undelete window, it regains this "
        "access without any new approval; stale bindings also make access reviews unreliable."
    ),
    "GCP-ORG-EXTERNAL-DOMAIN": (
        "Accounts managed by another organization can access this resource; if that party's "
        "accounts are compromised, or a person leaves without offboarding, the access remains."
    ),
    "GCP-ORG-FEDERATION": (
        "Identities from an external cloud or CI system can obtain Google credentials as this "
        "service account; with loose pool conditions, any workload in that system (for "
        "example any repository) could act as the service account."
    ),
    "GCP-NET-FW-ADMIN-INTERNET": (
        "If effective policies, routing and a listening service permit traffic, public "
        "sources could attempt administrative logins or exploit a vulnerable service. "
        "Reachability remains unverified. "
    ),
    "GCP-NET-FW-DB-INTERNET": (
        "If a matching database listener is reachable after effective policy evaluation, "
        "public sources could attempt authentication or exploit the engine. Data access is "
        "not established. "
    ),
    "GCP-NET-FW-ANY-INTERNET": (
        "An unrestricted rule could expose unintended listening services on matching public "
        "endpoints. Other policies, routes and service configuration may still block access. "
    ),
    "GCP-NET-DEFAULT-NETWORK": (
        "If permissive default rules remain, workloads placed in this network could gain "
        "unnecessary connectivity. A default network name alone does not establish those "
        "rules or connectivity. "
    ),
    "GCP-NET-FLOW-LOGS": (
        "Disabled subnet flow logging reduces connection evidence available from that "
        "configuration. Separate network logging or detection coverage requires validation. "
    ),
    "GCP-NET-PRIVATE-GOOGLE-ACCESS": (
        "Private workloads may depend on additional egress infrastructure to call Google "
        "APIs. Validate alternative private connectivity and workload requirements before "
        "treating this as exposure. "
    ),
    "GCP-VM-EXTERNAL-IP": (
        "If routing, effective firewalls and a listening service allow traffic, the assigned "
        "address could be targeted for scanning or unauthorized access attempts. "
    ),
    "GCP-VM-DEFAULT-SA": (
        "A compromised workload could use its attached identity within that identity's "
        "effective IAM permissions. The default account name establishes neither Editor "
        "access nor excessive privilege. "
    ),
    "GCP-VM-FULL-API-SCOPE": (
        "A compromised workload could request tokens usable across API families, within "
        "effective IAM grants. cloud-platform scope itself grants no IAM permissions and is "
        "recommended with narrowly scoped roles. "
    ),
    "GCP-VM-SERIAL-PORT": (
        "An identity with the required serial-console authorization could use a separate "
        "administration path if effective organization policy permits it. IAM, "
        "operating-system access and policy restrictions still apply. "
    ),
    "GCP-VM-OSLOGIN": (
        "Disabling OS Login can leave metadata-managed SSH keys outside the normal IAM login "
        "review. Operating-system support, alternative access controls and current keys "
        "require validation. "
    ),
    "GCP-VM-PROJECT-SSH-KEYS": (
        "With OS Login explicitly disabled, an authorized project SSH key could be accepted "
        "by multiple instances, increasing the impact of key disclosure if network and guest "
        "access permit login. "
    ),
    "GCP-VM-SHIELDED": (
        "Disabled boot-integrity controls can reduce resistance to or detection of boot-level "
        "tampering. Image support, guest controls and approved exceptions require review. "
    ),
    "GCP-VM-IP-FORWARD": (
        "A compromised forwarding-capable instance could participate in unintended routing if "
        "route and policy prerequisites also permit it. Approved network appliances may "
        "require this setting. "
    ),
    "GCP-STORAGE-UBLA": (
        "Object ACLs provide a separate access-management surface that may be missed by "
        "bucket IAM reviews. Actual public sharing and effective prevention require separate "
        "evidence. "
    ),
    "GCP-STORAGE-PAP": (
        "If effective prevention is absent, an accidental public IAM or ACL grant could "
        "expose objects. An inherited setting alone does not establish whether that guardrail "
        "is absent. "
    ),
    "GCP-STORAGE-VERSIONING": (
        "Overwrites or deletions could have fewer recovery options without object versions. "
        "Soft delete, retention policies and independent backups may provide other recovery "
        "mechanisms. "
    ),
    "GCP-SQL-OPEN-NETWORK": (
        "An unrestricted authorized network could allow public-source database connection "
        "attempts when the public endpoint and network path are available. Authentication and "
        "exploitation remain unverified. "
    ),
    "GCP-SQL-PUBLIC-IP": (
        "A public endpoint can increase the available connection surface. Authorized "
        "networks, connectors, authentication and effective reachability must be assessed "
        "separately. "
    ),
    "GCP-SQL-TLS": (
        "A connection made without transport encryption could expose credentials or data to "
        "an observer on the path. The metadata does not demonstrate that such a connection "
        "occurred. "
    ),
    "GCP-SQL-BACKUP": (
        "Disabled automated backups reduce one recovery mechanism after deletion or "
        "corruption. Independent backups and point-in-time recovery require separate "
        "validation. "
    ),
    "GCP-KMS-ROTATION": (
        "A longer rotation interval increases the amount of new data protected with one "
        "version. Key exposure is not established; the 90-day engineering baseline needs "
        "owner policy validation. "
    ),
    "GCP-LOG-RETENTION": (
        "If the approved investigation window exceeds the observed retention, required log "
        "evidence might expire before review. The approved retention objective must be "
        "established first. "
    ),
}

# Rule-specific impact for rules whose stored risk text is a shared generic sentence.
IMPACT = {
    "GCP-STORAGE-PUBLIC": (
        "Objects can be read by unauthenticated or any-Google-account principals, risking "
        "disclosure of the stored data. Data sensitivity is not established."
    ),
    "GCP-API-APP": "The key is usable from any website, app or IP address once leaked.",
    "GCP-API-API": (
        "The key is accepted by every enabled API in the project, not only those needed."
    ),
    "GCP-API-BOTH": "The key has neither caller nor API restrictions; possession alone grants use.",
    "GCP-KEY-PERSISTENT": (
        "A downloadable long-lived credential exists for the service account; anyone holding "
        "the key file can act as it."
    ),
    "GCP-KEY-AGE": (
        "The key has outlived the rotation policy, increasing the chance it was exposed while "
        "remaining valid."
    ),
    "GCP-KEY-PRIVILEGED": (
        "A long-lived key exists for a broadly privileged service account, so leaking the key "
        "would expose broad project control."
    ),
    "GCP-IAM-BASIC": (
        "Owner or Editor grants broad permissions across nearly all services in scope, far "
        "beyond typical job needs."
    ),
    "GCP-IAM-PUBLIC": (
        "A sensitive role is granted to public principals, making it usable by anyone."
    ),
    "GCP-IAM-IMPERSONATION": (
        "Broad impersonation rights let principals assume service-account identities and their "
        "privileges."
    ),
    "GCP-IAM-CROSSPROJECT": (
        "A service account from another project holds broad control here, extending trust "
        "across the project boundary."
    ),
    "GCP-GOV-KEYS": (
        "Service-account key creation or upload is not blocked by organization policy, so "
        "long-lived keys can be created freely."
    ),
    "GCP-LOG-AUDIT": (
        "Data Access audit logs are not recorded for some principals, reducing visibility of "
        "data access."
    ),
    "GCP-LOG-EXCLUSION": (
        "A logging exclusion drops matching entries before storage; security events may be "
        "among them."
    ),
    "GCP-SCC-OBSERVATION": (
        "An active Security Command Center finding exists for this resource; impact depends on "
        "the reported category."
    ),
}


# Misuse scenario per GCP domain rule family. Kept distinct from the rule's risk statement,
# which is the impact, so a finding never repeats one sentence under two headings.
DOMAIN_SCENARIO = {
    "Kubernetes": (
        "A caller holding cluster credentials, or code running in a compromised workload, "
        "could use the weaker setting to reach the control plane, nodes or other workloads "
        "further than the intended boundary allows."
    ),
    "Serverless": (
        "A caller admitted by IAM and ingress could invoke the workload; any further action "
        "depends on application flaws and the permissions of its runtime identity."
    ),
    "Edge Security": (
        "Traffic reaching the external load balancer would be handled without the "
        "expected edge control, such as a modern TLS policy, Cloud Armor or request logging."
    ),
    "Network and Exposure": (
        "Hosts reachable through the broad rule could receive connection attempts on "
        "sensitive ports from sources outside the approved ranges."
    ),
    "Monitoring and Detection": (
        "Activity that the configuration should record or alert on could go unnoticed, "
        "delaying detection and investigation."
    ),
    "Supply Chain": (
        "A changed build input or retagged image could be deployed without the expected "
        "review or immutability guarantee."
    ),
    "Identity and Access": (
        "A principal able to use the trust or role could act with permissions beyond the "
        "intended scope."
    ),
    "Data Security": (
        "A caller covered by the grant could read the data without belonging to the organization."
    ),
    "Database Security": (
        "A client or operator could rely on the weaker database setting; impact depends on "
        "network reachability and credentials."
    ),
    "Governance": (
        "Without the guardrail, an authorized administrator could create the configuration "
        "the constraint is meant to prevent."
    ),
    "Cryptography and Secrets": (
        "A secret that is never rotated stays usable for longer if it is copied or leaked."
    ),
    "Messaging": (
        "An endpoint receiving push messages could not verify that they came from the "
        "intended subscription."
    ),
}


def explain(finding) -> dict[str, str]:
    """Why flagged, how it can be misused, impact and recommendation for one candidate."""

    def field(name: str) -> str:
        value = finding.get(name) if isinstance(finding, dict) else getattr(finding, name, "")
        return value or ""

    rule = field("rule_id")
    advice = recommendation(rule)
    if rule.startswith("GCP-"):
        from offline_analyzer.rules.gcp_domains import SPECS

        if rule in SPECS:
            spec = SPECS[rule]
            return {
                "why_flagged": field("technical_observation"),
                "misuse": f"{DOMAIN_SCENARIO.get(spec.domain, spec.risk)} ({MISUSE_QUALIFIER})"
                if spec.domain in DOMAIN_SCENARIO
                else "Not yet described for this rule; analyst assessment required.",
                "impact": spec.risk,
                "recommendation": spec.remediation,
                "version": "clogcp-explanations-1.1.0",
            }
    misuse = MISUSE.get(rule)
    return {
        "why_flagged": field("technical_observation"),
        "misuse": f"{misuse} ({MISUSE_QUALIFIER})"
        if misuse
        else "Not yet described for this rule; analyst assessment required.",
        "impact": IMPACT.get(rule) or field("security_risk"),
        "recommendation": advice.get("recommended_action") or field("remediation"),
        "version": VERSION,
    }
