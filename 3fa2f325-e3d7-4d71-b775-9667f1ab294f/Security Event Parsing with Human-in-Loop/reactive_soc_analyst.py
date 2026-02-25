
# ══════════════════════════════════════════════════════════════════════════════
# REACTIVE SOC ANALYST  —  NetApp Storage Threat Triage Engine
# ══════════════════════════════════════════════════════════════════════════════
#
# Multi-step reasoning agent for every alert slice:
#   Step 1: Parse & classify threat → MITRE ATT&CK for Enterprise technique
#   Step 2: Contextual enrichment — volume snapshotability, replication,
#            encryption status, blast radius estimation
#   Step 3: Urgency scoring (1–10) weighted formula:
#              severity_weight  × 0.35
#            + asset_criticality × 0.30
#            + risk_score_norm   × 0.20
#            + verdict_weight    × 0.15
#   Step 4: Structured triage report with specific ONTAP/DII REST API calls
#
# Output: reactive_triage (dict, event_id → triage_report_dict)
# ══════════════════════════════════════════════════════════════════════════════

from datetime import datetime, timezone
from collections import Counter

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: MITRE ATT&CK MAPPING  (Enterprise, v14)
# ─────────────────────────────────────────────────────────────────────────────

# Maps event_type → (technique_id, technique_name, tactic, description)
_MITRE_MAP = {
    "RANSOMWARE": (
        "T1486",
        "Data Encrypted for Impact",
        "Impact",
        "Adversary encrypts data on target systems to interrupt availability. "
        "NetApp Workload Security detects mass file renames and encryption operations.",
    ),
    "MALWARE_DETECTED": (
        "T1204.002",
        "User Execution: Malicious File",
        "Execution",
        "Malicious file executed on NAS share or CIFS mount; vscan/FPolicy triggered.",
    ),
    "DATA_EXFILTRATION": (
        "T1030",
        "Data Transfer Size Limits",
        "Exfiltration",
        "Adversary transfers unusually large data volumes via network to avoid detection limits. "
        "DII Workload Security anomalous throughput spike flagged.",
    ),
    "BRUTE_FORCE": (
        "T1110",
        "Brute Force",
        "Credential Access",
        "Adversary attempts to gain access by guessing credentials. "
        "ONTAP EMS security.login.fail / security.account.lock events triggered.",
    ),
    "PRIVILEGE_ESCALATION": (
        "T1078",
        "Valid Accounts",
        "Privilege Escalation / Defense Evasion",
        "Adversary uses compromised or abused valid accounts to escalate privileges or "
        "access resources outside normal scope. service account lateral volume access.",
    ),
    "UNAUTHORIZED_ACCESS": (
        "T1078",
        "Valid Accounts",
        "Initial Access / Lateral Movement",
        "Unauthorised access to restricted storage resource; FPolicy blocked or "
        "CIFS/NFS auth bypass attempted.",
    ),
    "SQL_INJECTION": (
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        "Exploitation of SQL injection vulnerability in an application with storage backend; "
        "credential or data extraction target.",
    ),
    "PORT_SCAN": (
        "T1046",
        "Network Service Discovery",
        "Discovery",
        "Adversary performs port scanning to enumerate reachable storage services "
        "(NFS 2049, CIFS 445, iSCSI 3260, ONTAP HTTPS 443).",
    ),
    "POLICY_VIOLATION": (
        "T1562.001",
        "Impair Defenses: Disable or Modify Tools",
        "Defense Evasion",
        "Firewall policy or FPolicy rule violation — adversary may be probing for "
        "gaps in perimeter defenses or attempting to disable security controls.",
    ),
    "ANOMALOUS_IO": (
        "T1496",
        "Resource Hijacking",
        "Impact",
        "Abnormal I/O profile (throughput/IOPS spike) — potential cryptomining, "
        "data staging, or exfiltration preparation.",
    ),
    "AUDIT_EVENT": (
        "T1070.002",
        "Indicator Removal: Clear Linux or Mac System Logs",
        "Defense Evasion",
        "Audit log manipulation or tampering attempt — adversary may attempt to "
        "clear evidence of prior activity.",
    ),
    "CAPACITY_ALERT": (
        "T1485",
        "Data Destruction",
        "Impact",
        "Volume at capacity — potential log flooding, data destruction, or "
        "denial-of-service via storage exhaustion.",
    ),
    "CERTIFICATE_ALERT": (
        "T1552.004",
        "Unsecured Credentials: Private Keys",
        "Credential Access",
        "Expiring certificate creates window for man-in-the-middle or credential abuse.",
    ),
}

_DEFAULT_MITRE = (
    "T1059",
    "Command and Scripting Interpreter",
    "Execution",
    "Unclassified storage event — further investigation required.",
)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: CONTEXTUAL ENRICHMENT  — Volume & SVM Asset Intelligence
# ─────────────────────────────────────────────────────────────────────────────

# Asset criticality tiers mapped to known SVM/volume naming patterns
# (In production these would be queried from ONTAP: GET /storage/volumes/<uuid>)
_ASSET_CRITICALITY_MAP = {
    "svm-prod":  "TIER_1_CRITICAL",    # Production SVM — max blast radius
    "svm-dr":    "TIER_1_CRITICAL",    # DR SVM — equally sensitive
    "svm-dev":   "TIER_2_HIGH",        # Dev SVM — elevated but not prod
    "svm-test":  "TIER_3_MEDIUM",
    "svm-dmz":   "TIER_2_HIGH",        # DMZ-facing SVM
    "prod_data": "TIER_1_CRITICAL",
    "finance":   "TIER_1_CRITICAL",
    "hr":        "TIER_1_CRITICAL",
    "backup":    "TIER_2_HIGH",
    "dev":       "TIER_2_HIGH",
    "staging":   "TIER_3_MEDIUM",
    "test":      "TIER_3_MEDIUM",
    "log":       "TIER_3_MEDIUM",
}

_CRITICALITY_SCORE = {
    "TIER_1_CRITICAL": 10,
    "TIER_2_HIGH":     7,
    "TIER_3_MEDIUM":   4,
    "TIER_4_LOW":      2,
    "UNKNOWN":         5,  # conservative default
}


def _infer_asset_criticality(alert_dict: dict) -> tuple:
    """
    Infer asset criticality from SVM name, volume description, or source.
    Returns (criticality_tier, criticality_score, asset_notes).
    """
    _svm  = str(alert_dict.get("svm", "")).lower()
    _node = str(alert_dict.get("node", "")).lower()
    _desc = str(alert_dict.get("description", "")).lower()
    _src  = str(alert_dict.get("source", "")).lower()

    # Check SVM name
    for _key, _tier in _ASSET_CRITICALITY_MAP.items():
        if _key in _svm:
            return (
                _tier, _CRITICALITY_SCORE[_tier],
                f"SVM '{_svm}' matches criticality pattern '{_key}'.",
            )

    # Check description for volume name patterns
    for _key, _tier in _ASSET_CRITICALITY_MAP.items():
        if _key in _desc:
            return (
                _tier, _CRITICALITY_SCORE[_tier],
                f"Volume/description contains '{_key}' — inferred criticality.",
            )

    # DII alerts touching production volumes default to TIER_1
    if _src == "dii" and "prod" in _desc:
        return ("TIER_1_CRITICAL", 10, "DII event on production-tagged volume.")

    # ONTAP_EMS on production nodes
    if _src == "ontap_ems" and _node:
        return ("TIER_2_HIGH", 7, f"ONTAP EMS event on node '{_node}'.")

    return ("UNKNOWN", 5, "Could not determine asset criticality — applying conservative score.")


def _assess_snapshot_posture(alert_dict: dict) -> dict:
    """
    Simulate volume snapshot/replication/encryption assessment.
    In production: query ONTAP GET /storage/volumes?svm.name=<svm>&fields=snapshot_policy,
    protection.destination,encryption.enabled
    """
    _svm  = str(alert_dict.get("svm", "")).lower()
    _src  = str(alert_dict.get("source", "")).lower()
    _desc = str(alert_dict.get("description", "")).lower()
    _etype = alert_dict.get("event_type", "")

    # Simulate posture based on SVM tier
    if "prod" in _svm or "dr" in _svm:
        _snap   = True
        _repl   = True
        _encr   = True
        _policy = "hourly-24-daily-7-weekly-4"
    elif "dev" in _svm or "staging" in _svm:
        _snap   = True
        _repl   = False
        _encr   = False
        _policy = "default-1-week"
    else:
        _snap   = False
        _repl   = False
        _encr   = False
        _policy = "none"

    # Ransomware — check if snapshots are likely locked (SnapLock)
    _snaplock = "prod" in _svm and _etype in ("RANSOMWARE", "MALWARE_DETECTED")

    return {
        "snapshots_enabled":   _snap,
        "snapshot_policy":     _policy,
        "snaplock_protected":  _snaplock,
        "replication_enabled": _repl,
        "encryption_enabled":  _encr,
        "recovery_point_obj":  "≤ 1 hour" if _snap else "NONE — full data loss risk",
        "ontap_query": (
            f"GET /api/storage/volumes?svm.name={_svm or '<svm>'}"
            "&fields=name,snapshot_policy,protection.destination,"
            "encryption.enabled,snaplock.type,space.used,space.available"
        ),
    }


def _estimate_blast_radius(alert_dict: dict, asset_tier: str) -> dict:
    """Estimate blast radius for this event based on type, asset tier, and source."""
    _etype = alert_dict.get("event_type", "")
    _sev   = alert_dict.get("severity", "LOW")
    _src   = alert_dict.get("source", "UNKNOWN")

    # High-blast events
    _wide_blast = _etype in (
        "RANSOMWARE", "DATA_EXFILTRATION", "PRIVILEGE_ESCALATION",
        "UNAUTHORIZED_ACCESS", "MALWARE_DETECTED"
    )
    _is_crit = _sev in ("CRITICAL",)
    _is_high = _sev in ("HIGH",)

    if _is_crit and _wide_blast and "TIER_1" in asset_tier:
        _scope  = "CLUSTER-WIDE"
        _impact = "All SVMs and volumes on the cluster; potential SnapMirror cascade to DR."
        _est_files_at_risk = "ALL production volumes"
        _data_at_risk_gb   = "500–5000 GB"
    elif _is_crit or (_is_high and _wide_blast):
        _scope  = "SVM-WIDE"
        _impact = "All volumes within the affected SVM; NAS shares, CIFS/NFS exports."
        _est_files_at_risk = "All volumes in SVM"
        _data_at_risk_gb   = "100–1000 GB"
    elif _is_high or ("TIER_1" in asset_tier):
        _scope  = "VOLUME-LEVEL"
        _impact = "Single or few volumes; contained to affected qtree/share."
        _est_files_at_risk = "1–10 volumes"
        _data_at_risk_gb   = "10–200 GB"
    else:
        _scope  = "LOCAL"
        _impact = "Single file, session, or log stream. Limited lateral risk."
        _est_files_at_risk = "< 10 files"
        _data_at_risk_gb   = "< 10 GB"

    return {
        "blast_scope":         _scope,
        "impact_description":  _impact,
        "estimated_files_at_risk": _est_files_at_risk,
        "estimated_data_at_risk":  _data_at_risk_gb,
        "lateral_movement_risk": "HIGH" if _wide_blast and _is_crit else "MEDIUM" if _is_high else "LOW",
        "cascading_dr_risk":   "YES — SnapMirror may replicate ransomware payload" if _etype == "RANSOMWARE" else "LOW",
    }


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: URGENCY SCORING FORMULA  (1–10)
# ─────────────────────────────────────────────────────────────────────────────

_SEV_WEIGHT  = {"CRITICAL": 10.0, "HIGH": 7.5, "MEDIUM": 4.0, "LOW": 1.5, "INFO": 0.5}
_VERDICT_WEIGHT = {
    "ESCALATE":     10.0,
    "INVESTIGATE":  6.0,
    "DISMISS":      1.0,
    "PASS_THROUGH": 3.0,
}

def _compute_urgency_score(
    alert_dict: dict,
    asset_criticality_score: float,
    human_verdict: str,
) -> tuple:
    """
    Weighted urgency formula:
      severity_norm      × 0.35   (normalised 0–10)
      asset_criticality  × 0.30   (0–10)
      risk_score_norm    × 0.20   (0–10, from process_alert 0–15 scale)
      verdict_weight     × 0.15   (0–10)

    Returns (urgency_int_1_to_10, formula_breakdown_str)
    """
    _sev   = alert_dict.get("severity", "LOW")
    _rscore = alert_dict.get("risk_score", 0)

    _sw  = _SEV_WEIGHT.get(_sev, 1.0)                       # 0–10
    _aw  = float(asset_criticality_score)                    # 0–10
    _rw  = min(10.0, (_rscore / 15.0) * 10.0)               # 0–10 normalised
    _vw  = _VERDICT_WEIGHT.get(human_verdict, 3.0)           # 0–10

    _raw = (0.35 * _sw) + (0.30 * _aw) + (0.20 * _rw) + (0.15 * _vw)
    _urgency = max(1, min(10, round(_raw)))

    _breakdown = (
        f"severity={_sev}(×0.35={0.35*_sw:.2f}) + "
        f"asset_crit={asset_criticality_score}(×0.30={0.30*_aw:.2f}) + "
        f"risk_norm={_rw:.1f}(×0.20={0.20*_rw:.2f}) + "
        f"verdict={human_verdict}(×0.15={0.15*_vw:.2f}) "
        f"→ raw={_raw:.2f} → urgency={_urgency}/10"
    )
    return _urgency, _breakdown


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: ONTAP / DII REMEDIATION API CALLS
# ─────────────────────────────────────────────────────────────────────────────

def _build_remediation_api_calls(
    alert_dict: dict,
    snapshot_posture: dict,
    mitre_id: str,
) -> list:
    """
    Generate specific, executable ONTAP REST API and DII API calls
    for containment and remediation. Returns ordered list of dicts:
      { priority, action, method, endpoint, payload, description }
    """
    _etype  = alert_dict.get("event_type", "")
    _svm    = alert_dict.get("svm", "<svm-name>") or "<svm-name>"
    _src_ip = alert_dict.get("source_ip", "0.0.0.0")
    _node   = alert_dict.get("node", "<node>") or "<node>"
    _eid    = alert_dict.get("event_id", "")
    _sev    = alert_dict.get("severity", "LOW")

    _calls = []

    # ── 1. UNIVERSAL: Create forensic snapshot before any changes ────────
    if snapshot_posture.get("snapshots_enabled"):
        _calls.append({
            "priority":    1,
            "action":      "FORENSIC_SNAPSHOT",
            "method":      "POST",
            "endpoint":    f"/api/storage/volumes/{{volume_uuid}}/snapshots",
            "payload":     {
                "name": f"forensic-{_eid[:8]}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
                "comment": f"Forensic snapshot — reactive SOC triage for event {_eid} ({_etype})",
            },
            "description": "Preserve pre-incident state; required for forensics and recovery.",
            "curl_example": (
                f"curl -X POST https://$ONTAP_HOST/api/storage/volumes/$VOLUME_UUID/snapshots "
                f"-u $ONTAP_USER:$ONTAP_PASSWORD -k "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"name\":\"forensic-{_eid[:8]}\",\"comment\":\"SOC triage snapshot\"}}'"
            ),
        })

    # ── Event-type specific containment ──────────────────────────────────

    if _etype in ("RANSOMWARE", "MALWARE_DETECTED"):
        # Immediate: Suspend offending user/client via Workload Security
        _calls.append({
            "priority":    2,
            "action":      "SUSPEND_USER_DII_WORKLOAD_SECURITY",
            "method":      "PATCH",
            "endpoint":    f"/rest/v1/workloadSecurity/users/{{user_id}}",
            "payload":     {"status": "suspended", "reason": f"SOC reactive triage: {_etype} event {_eid}"},
            "description": "Immediately suspend the offending user account in DII Workload Security.",
            "curl_example": (
                "curl -X PATCH https://$DII_TENANT_URL/rest/v1/workloadSecurity/users/$USER_ID "
                "-H 'X-CloudInsights-ApiKey: $DII_API_TOKEN' "
                "-H 'Content-Type: application/json' "
                "-d '{\"status\":\"suspended\",\"reason\":\"SOC ransomware response\"}'"
            ),
        })
        # Snapshot-restore candidate if ransomware
        if _etype == "RANSOMWARE":
            _calls.append({
                "priority":    3,
                "action":      "INITIATE_SNAPRESTORE_DRY_RUN",
                "method":      "POST",
                "endpoint":    "/api/storage/volumes/{volume_uuid}/snapshots/{snapshot_uuid}/restore",
                "payload":     {
                    "restore_to":  "most_recent_clean_snapshot",
                    "dry_run":     True,
                    "comment":     f"Ransomware recovery candidate — event {_eid}",
                },
                "description": "Dry-run SnapRestore to identify most recent clean recovery point.",
                "curl_example": (
                    "curl -X POST https://$ONTAP_HOST/api/storage/volumes/$VOLUME_UUID/"
                    "snapshots/$SNAPSHOT_UUID/restore "
                    "-u $ONTAP_USER:$ONTAP_PASSWORD -k "
                    "-H 'Content-Type: application/json' "
                    "-d '{\"dry_run\":true}'"
                ),
            })
            # Break SnapMirror if DR replication is active (prevent ransomware cascade)
            if snapshot_posture.get("replication_enabled"):
                _calls.append({
                    "priority":    4,
                    "action":      "BREAK_SNAPMIRROR_REPLICATION",
                    "method":      "POST",
                    "endpoint":    f"/api/snapmirror/relationships/{{relationship_uuid}}/break",
                    "payload":     {},
                    "description": (
                        "CRITICAL: Break SnapMirror replication to prevent ransomware payload "
                        "cascading to DR site. Re-establish after clean recovery."
                    ),
                    "curl_example": (
                        "curl -X POST https://$ONTAP_HOST/api/snapmirror/relationships/"
                        "$RELATIONSHIP_UUID/break "
                        "-u $ONTAP_USER:$ONTAP_PASSWORD -k "
                        "-H 'Content-Type: application/json' -d '{}'"
                    ),
                })
        # FPolicy: block all writes immediately
        _calls.append({
            "priority":    5 if _etype == "RANSOMWARE" else 3,
            "action":      "FPOLICY_BLOCK_SUSPICIOUS_EXTENSIONS",
            "method":      "POST",
            "endpoint":    f"/api/protocols/fpolicy",
            "payload":     {
                "svm":     {"name": _svm},
                "policy":  {
                    "name": "ransomware-emergency-block",
                    "events": [{"name": "write-create-rename"}],
                    "engine": {"name": "native"},
                    "mandatory": True,
                },
                "scope": {
                    "file_extensions_to_include": [
                        ".encrypted", ".locked", ".crypt", ".ransom",
                        ".cerber", ".locky", ".cryp1", ".zepto",
                    ],
                },
            },
            "description": "Enable FPolicy to block writes of known ransomware-encrypted file extensions.",
            "curl_example": (
                f"curl -X POST https://$ONTAP_HOST/api/protocols/fpolicy "
                f"-u $ONTAP_USER:$ONTAP_PASSWORD -k "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"svm\":{{\"name\":\"{_svm}\"}},\"policy\":{{\"name\":\"ransomware-block\",\"mandatory\":true}}}}'"
            ),
        })

    elif _etype == "BRUTE_FORCE":
        # Lock the targeted account
        _calls.append({
            "priority":    2,
            "action":      "LOCK_ONTAP_ACCOUNT",
            "method":      "PATCH",
            "endpoint":    "/api/security/accounts/{account_name}",
            "payload":     {"locked": True, "comment": f"SOC emergency lock: brute force from {_src_ip}"},
            "description": f"Lock the targeted ONTAP account to stop brute-force credential access from {_src_ip}.",
            "curl_example": (
                f"curl -X PATCH https://$ONTAP_HOST/api/security/accounts/$ACCOUNT_NAME "
                f"-u $ONTAP_USER:$ONTAP_PASSWORD -k "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"locked\":true}}'"
            ),
        })
        # Block source IP via network security group or firewall policy
        _calls.append({
            "priority":    3,
            "action":      "CREATE_LOGIN_BANNER_AND_AUDIT_RULE",
            "method":      "PATCH",
            "endpoint":    "/api/security/audit",
            "payload":     {
                "enabled": True,
                "log_path": "/mroot/etc/log/mlog",
                "events": {
                    "authorization_policy": True,
                    "system_management":    True,
                },
            },
            "description": "Enable comprehensive audit logging to capture all subsequent authentication events.",
            "curl_example": (
                "curl -X PATCH https://$ONTAP_HOST/api/security/audit "
                "-u $ONTAP_USER:$ONTAP_PASSWORD -k "
                "-H 'Content-Type: application/json' "
                "-d '{\"enabled\":true,\"events\":{\"authorization_policy\":true}}'"
            ),
        })
        # Query all accounts for compromise indicators
        _calls.append({
            "priority":    4,
            "action":      "ENUMERATE_ACCOUNTS_FOR_LOCKOUT",
            "method":      "GET",
            "endpoint":    f"/api/security/accounts?locked=false&fields=name,locked,applications",
            "payload":     {},
            "description": "List all active ONTAP accounts to identify other potentially compromised credentials.",
            "curl_example": (
                "curl -X GET 'https://$ONTAP_HOST/api/security/accounts?locked=false&fields=name,locked,applications' "
                "-u $ONTAP_USER:$ONTAP_PASSWORD -k"
            ),
        })

    elif _etype in ("DATA_EXFILTRATION", "ANOMALOUS_IO"):
        # Rate-limit or snapshot the affected volume
        _calls.append({
            "priority":    2,
            "action":      "APPLY_VOLUME_QOS_THROTTLE",
            "method":      "PATCH",
            "endpoint":    "/api/storage/volumes/{volume_uuid}",
            "payload":     {
                "qos": {
                    "policy": {
                        "max_throughput_iops": 100,
                        "max_throughput_mbps": 5,
                    }
                },
                "comment": f"Emergency QoS throttle — SOC exfiltration response event {_eid}",
            },
            "description": "Apply aggressive QoS policy to starve exfiltration bandwidth on affected volume.",
            "curl_example": (
                "curl -X PATCH https://$ONTAP_HOST/api/storage/volumes/$VOLUME_UUID "
                "-u $ONTAP_USER:$ONTAP_PASSWORD -k "
                "-H 'Content-Type: application/json' "
                "-d '{\"qos\":{\"policy\":{\"max_throughput_mbps\":5}}}'"
            ),
        })
        # Query DII for active exfiltration path
        _calls.append({
            "priority":    3,
            "action":      "DII_QUERY_WORKLOAD_ACTIVITY",
            "method":      "GET",
            "endpoint":    f"/rest/v1/workloadSecurity/activities?startTime={{epoch_ms}}&user={{user}}&limit=100",
            "payload":     {},
            "description": "Pull all anomalous file access activities from DII to identify exfil target files.",
            "curl_example": (
                "curl -X GET 'https://$DII_TENANT_URL/rest/v1/workloadSecurity/activities?"
                "startTime=$EPOCH_MS&limit=100' "
                "-H 'X-CloudInsights-ApiKey: $DII_API_TOKEN'"
            ),
        })
        # CIFS/NFS session kill for source IP
        _calls.append({
            "priority":    4,
            "action":      "KILL_CLIENT_SESSION",
            "method":      "DELETE",
            "endpoint":    f"/api/protocols/cifs/sessions?client_ip={_src_ip}&svm.name={_svm}",
            "payload":     {},
            "description": f"Terminate all active CIFS sessions from source IP {_src_ip} on SVM {_svm}.",
            "curl_example": (
                f"curl -X DELETE 'https://$ONTAP_HOST/api/protocols/cifs/sessions?"
                f"client_ip={_src_ip}&svm.name={_svm}' "
                f"-u $ONTAP_USER:$ONTAP_PASSWORD -k"
            ),
        })

    elif _etype in ("PRIVILEGE_ESCALATION", "UNAUTHORIZED_ACCESS"):
        # Audit role assignments
        _calls.append({
            "priority":    2,
            "action":      "AUDIT_RBAC_ROLES",
            "method":      "GET",
            "endpoint":    "/api/security/roles?fields=name,privileges,svm.name",
            "payload":     {},
            "description": "Enumerate all RBAC roles to identify misconfigured or over-privileged assignments.",
            "curl_example": (
                "curl -X GET 'https://$ONTAP_HOST/api/security/roles?fields=name,privileges,svm.name' "
                "-u $ONTAP_USER:$ONTAP_PASSWORD -k"
            ),
        })
        # Restrict account to specific SVM
        _calls.append({
            "priority":    3,
            "action":      "RESTRICT_ACCOUNT_SVM_SCOPE",
            "method":      "PATCH",
            "endpoint":    f"/api/security/accounts/{{account_name}}",
            "payload":     {
                "svm": {"name": _svm},
                "applications": [
                    {"application": "ssh",   "authentication_methods": ["password"]},
                    {"application": "ontapi","authentication_methods": ["password"]},
                ],
                "comment": f"SOC restriction: scoped to {_svm} post-privilege-escalation event {_eid}",
            },
            "description": f"Restrict account scope to SVM '{_svm}' and disable extraneous application methods.",
            "curl_example": (
                f"curl -X PATCH https://$ONTAP_HOST/api/security/accounts/$ACCOUNT_NAME "
                f"-u $ONTAP_USER:$ONTAP_PASSWORD -k "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"svm\":{{\"name\":\"{_svm}\"}}}}'"
            ),
        })
        # Enable FPolicy for the SVM
        _calls.append({
            "priority":    4,
            "action":      "ENABLE_FPOLICY_AUDIT_SVM",
            "method":      "PATCH",
            "endpoint":    f"/api/protocols/fpolicy/{{policy_uuid}}",
            "payload":     {"enabled": True},
            "description": f"Enable FPolicy audit engine on SVM '{_svm}' to capture all file-access events.",
            "curl_example": (
                f"curl -X PATCH https://$ONTAP_HOST/api/protocols/fpolicy/$POLICY_UUID "
                f"-u $ONTAP_USER:$ONTAP_PASSWORD -k "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"enabled\":true}}'"
            ),
        })

    elif _etype in ("PORT_SCAN", "SQL_INJECTION", "POLICY_VIOLATION"):
        # Create EMS filter to alert on further probing
        _calls.append({
            "priority":    2,
            "action":      "CREATE_EMS_ALERT_FILTER",
            "method":      "POST",
            "endpoint":    "/api/support/ems/filters",
            "payload":     {
                "name": f"soc-probe-watch-{_eid[:8]}",
                "rules": [
                    {
                        "type":             "include",
                        "message_criteria": {
                            "severities":   "emergency,alert,error",
                            "name_pattern": "net.firewall.*",
                        },
                    },
                    {
                        "type":             "include",
                        "message_criteria": {
                            "severities":   "emergency,alert,error",
                            "name_pattern": "security.login.*",
                        },
                    },
                ],
            },
            "description": f"Create EMS filter to catch follow-on network/auth events from {_src_ip}.",
            "curl_example": (
                "curl -X POST https://$ONTAP_HOST/api/support/ems/filters "
                "-u $ONTAP_USER:$ONTAP_PASSWORD -k "
                "-H 'Content-Type: application/json' "
                "-d '{\"name\":\"soc-probe-watch\",\"rules\":[{\"type\":\"include\","
                "\"message_criteria\":{\"severities\":\"emergency,alert\",\"name_pattern\":\"net.*\"}}]}'"
            ),
        })
        # Register EMS webhook to SOC endpoint
        _calls.append({
            "priority":    3,
            "action":      "REGISTER_EMS_WEBHOOK",
            "method":      "POST",
            "endpoint":    "/api/support/ems/destinations",
            "payload":     {
                "name":        f"soc-webhook-{_eid[:8]}",
                "type":        "rest_api",
                "destination": "https://<your-soc-siem-endpoint>/api/ems",
                "filters":     [{"name": f"soc-probe-watch-{_eid[:8]}"}],
            },
            "description": "Register EMS REST webhook to forward future events to SOC SIEM in real time.",
            "curl_example": (
                "curl -X POST https://$ONTAP_HOST/api/support/ems/destinations "
                "-u $ONTAP_USER:$ONTAP_PASSWORD -k "
                "-H 'Content-Type: application/json' "
                "-d '{\"name\":\"soc-webhook\",\"type\":\"rest_api\","
                "\"destination\":\"https://soc.example.com/api/ems\"}'"
            ),
        })

    # ── UNIVERSAL: Poll DII for correlated anomaly alerts ────────────────
    _calls.append({
        "priority":    len(_calls) + 1,
        "action":      "DII_QUERY_CORRELATED_ALERTS",
        "method":      "GET",
        "endpoint":    f"/rest/v1/alerts?startTime={{epoch_ms}}&severity=critical,warning&status=active&limit=50",
        "payload":     {},
        "description": "Query DII for all active correlated alerts to identify campaign-level activity.",
        "curl_example": (
            "curl -X GET 'https://$DII_TENANT_URL/rest/v1/alerts?"
            "status=active&severity=critical&limit=50' "
            "-H 'X-CloudInsights-ApiKey: $DII_API_TOKEN'"
        ),
    })

    # ── UNIVERSAL: EMS event fetch for audit trail ────────────────────────
    _calls.append({
        "priority":    len(_calls) + 1,
        "action":      "ONTAP_EMS_AUDIT_FETCH",
        "method":      "GET",
        "endpoint":    (
            "/api/support/ems/events?time.gte={iso_time_minus_1h}"
            "&message.severity=emergency,alert,critical,error"
            "&fields=index,time,message.name,message.severity,node.name,"
            "svm.name,log_message,parameters&max_records=100"
        ),
        "payload":     {},
        "description": "Pull last 1 hour of high-severity EMS events for forensic audit trail.",
        "curl_example": (
            "curl -X GET 'https://$ONTAP_HOST/api/support/ems/events?"
            "time.gte=$(date -u -d \"1 hour ago\" +%Y-%m-%dT%H:%M:%SZ)"
            "&message.severity=emergency,alert,critical,error&max_records=100' "
            "-u $ONTAP_USER:$ONTAP_PASSWORD -k"
        ),
    })

    return sorted(_calls, key=lambda x: x["priority"])


# ─────────────────────────────────────────────────────────────────────────────
# RECOMMENDED ACTIONS  — ranked per threat class
# ─────────────────────────────────────────────────────────────────────────────

_RECOMMENDED_ACTIONS = {
    "RANSOMWARE": [
        "1. [IMMEDIATE] Break SnapMirror replication to prevent DR site infection.",
        "2. [IMMEDIATE] Suspend offending user account via DII Workload Security API.",
        "3. [IMMEDIATE] Enable FPolicy emergency extension block on SVM.",
        "4. [<5 MIN] Create forensic snapshot of all affected volumes.",
        "5. [<5 MIN] Initiate SnapRestore dry-run to identify clean recovery point.",
        "6. [<15 MIN] Notify CISO and IR team — open Priority-1 incident.",
        "7. [<30 MIN] Identify all encrypted files via DII workloadSecurity/activities.",
        "8. [<1 HR] Execute SnapRestore from last clean snapshot on isolated SVM.",
        "9. [<2 HR] Conduct root-cause analysis — initial access vector.",
        "10. [POST-IR] Harden access: enforce MFA, rotate all SVM credentials.",
    ],
    "DATA_EXFILTRATION": [
        "1. [IMMEDIATE] Terminate active CIFS/NFS session from source IP.",
        "2. [IMMEDIATE] Apply emergency QoS throttle on affected volume.",
        "3. [<5 MIN] Create forensic snapshot before session teardown.",
        "4. [<5 MIN] Collect DII Workload Security activity log for affected user.",
        "5. [<15 MIN] Identify all files accessed in anomalous session.",
        "6. [<15 MIN] Block source IP at perimeter firewall and NetApp network policy.",
        "7. [<30 MIN] Escalate to DLP team for data classification review.",
        "8. [<1 HR] Notify Legal/Compliance if regulated data (PII/PCI/HIPAA) affected.",
    ],
    "BRUTE_FORCE": [
        "1. [IMMEDIATE] Lock targeted ONTAP account via /api/security/accounts.",
        "2. [IMMEDIATE] Block source IP at perimeter — confirmed Tor exit / scanner.",
        "3. [<5 MIN] Enumerate all accounts for concurrent lockout indicators.",
        "4. [<5 MIN] Enable comprehensive audit logging on ONTAP cluster.",
        "5. [<15 MIN] Review last 24h EMS security.login.fail events for pattern.",
        "6. [<30 MIN] Force password rotation for all accounts accessed from source IP.",
        "7. [<1 HR] Review MFA enforcement — enforce certificate or TOTP for SSH/API.",
        "8. [<2 HR] Threat hunt for lateral movement post-compromise indicators.",
    ],
    "MALWARE_DETECTED": [
        "1. [IMMEDIATE] Isolate affected CIFS share — restrict access via NTFS ACL.",
        "2. [IMMEDIATE] Trigger Vscan full-volume scan via /api/protocols/vscan.",
        "3. [<5 MIN] Create forensic snapshot before quarantine action.",
        "4. [<5 MIN] Suspend user account that introduced malware.",
        "5. [<15 MIN] Identify patient-zero endpoint — coordinate with endpoint security team.",
        "6. [<30 MIN] Review FPolicy event log for other affected file paths.",
        "7. [<1 HR] Scan all volumes in SVM for same malware signature.",
    ],
    "PRIVILEGE_ESCALATION": [
        "1. [IMMEDIATE] Restrict account to minimum required SVM scope.",
        "2. [<5 MIN] Audit RBAC role assignments — revoke excess privileges.",
        "3. [<5 MIN] Enable FPolicy audit mode on affected SVM.",
        "4. [<15 MIN] Review all volume access events for the escalated account (24h).",
        "5. [<30 MIN] Force account re-authentication after scope restriction.",
        "6. [<1 HR] Review service account permissions — implement least privilege.",
    ],
    "UNAUTHORIZED_ACCESS": [
        "1. [IMMEDIATE] Deny access via ONTAP export policy rule update.",
        "2. [<5 MIN] Audit NFS/CIFS export policies for over-permissive rules.",
        "3. [<15 MIN] Review FPolicy blocked event details.",
        "4. [<30 MIN] Correlate with AD/LDAP for account status.",
        "5. [<1 HR] Review all access attempts from source IP across all SVMs.",
    ],
    "SQL_INJECTION": [
        "1. [IMMEDIATE] Block source IP at WAF and network perimeter.",
        "2. [<15 MIN] Review application logs for full injection payload analysis.",
        "3. [<30 MIN] Check storage backend for unauthorized data access via app.",
        "4. [<1 HR] Rotate application database credentials.",
        "5. [<2 HR] Apply WAF rule to block identified injection pattern.",
    ],
    "PORT_SCAN": [
        "1. [<5 MIN] Block scanning IP at perimeter firewall.",
        "2. [<15 MIN] Register EMS webhook for real-time follow-on alerting.",
        "3. [<30 MIN] Audit exposed storage service ports (NFS 2049, CIFS 445, iSCSI 3260).",
        "4. [<1 HR] Threat hunt for subsequent exploitation attempts from same IP range.",
        "5. [<2 HR] Review network segmentation — storage SVMs should not be internet-reachable.",
    ],
    "POLICY_VIOLATION": [
        "1. [<5 MIN] Review firewall policy violation details — identify mis-classified traffic.",
        "2. [<15 MIN] Create targeted EMS filter for follow-on network events.",
        "3. [<30 MIN] Audit firewall policy rule set for gaps.",
        "4. [<1 HR] Check if any storage services were reached post-violation.",
    ],
    "ANOMALOUS_IO": [
        "1. [IMMEDIATE] Apply QoS policy to throttle abnormal I/O on affected volume.",
        "2. [<5 MIN] Query DII metrics for I/O pattern timeline.",
        "3. [<15 MIN] Identify process/session driving the anomalous I/O.",
        "4. [<30 MIN] Check for cryptomining indicators (constant high CPU + I/O).",
        "5. [<1 HR] Review volume capacity and snapshot schedule for backup impact.",
    ],
}

_DEFAULT_ACTIONS = [
    "1. [IMMEDIATE] Create forensic snapshot of affected volume.",
    "2. [<15 MIN] Pull EMS event history for affected SVM/node.",
    "3. [<30 MIN] Review DII correlated alerts.",
    "4. [<1 HR] Assess user/process responsible for the event.",
    "5. [<2 HR] Escalate if additional indicators found.",
]


# ─────────────────────────────────────────────────────────────────────────────
# DECISION LOOKUP: Build human_decision lookup by event_id
# ─────────────────────────────────────────────────────────────────────────────

# human_decision is a single dict (from human_review block)
# pass_through_decisions is a list of dicts
_decision_lookup = {}

# If human_decision is a single dict (one top alert)
if isinstance(human_decision, dict):
    _decision_lookup[human_decision["event_id"]] = human_decision
elif isinstance(human_decision, list):
    for _d in human_decision:
        _decision_lookup[_d["event_id"]] = _d

# Add pass_through_decisions
for _d in pass_through_decisions:
    _decision_lookup[_d["event_id"]] = _d


# ─────────────────────────────────────────────────────────────────────────────
# MAIN TRIAGE LOOP  — process every enriched alert
# ─────────────────────────────────────────────────────────────────────────────

reactive_triage = {}   # OUTPUT: dict keyed by event_id

_W = 76
print(f"{'═'*_W}")
print(f"  🛡  REACTIVE SOC ANALYST  —  NetApp Storage Threat Triage Engine")
print(f"  Processing {len(enriched_alert)} alert(s) | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
print(f"{'═'*_W}\n")

for _alert in sorted(enriched_alert, key=lambda a: -a["risk_score"]):
    _eid   = _alert["event_id"]
    _etype = _alert["event_type"]
    _sev   = _alert["severity"]

    # ── Step 1: MITRE ATT&CK Classification ──────────────────────────────
    _mitre_id, _mitre_name, _mitre_tactic, _mitre_desc = _MITRE_MAP.get(
        _etype, _DEFAULT_MITRE
    )
    _threat_class = (
        f"{_etype.replace('_', ' ').title()} — {_mitre_name} "
        f"(MITRE {_mitre_id}, Tactic: {_mitre_tactic})"
    )

    # ── Step 2: Contextual Enrichment ────────────────────────────────────
    _asset_tier, _asset_cscore, _asset_notes = _infer_asset_criticality(_alert)
    _snap_posture = _assess_snapshot_posture(_alert)
    _blast        = _estimate_blast_radius(_alert, _asset_tier)

    # ── Step 3: Urgency Scoring ───────────────────────────────────────────
    _dec    = _decision_lookup.get(_eid, {})
    _verdict = _dec.get("verdict", "PASS_THROUGH")
    _urgency, _urgency_breakdown = _compute_urgency_score(
        _alert, _asset_cscore, _verdict
    )

    # ── Step 4: Build report ──────────────────────────────────────────────
    _api_calls = _build_remediation_api_calls(_alert, _snap_posture, _mitre_id)
    _rec_actions = _RECOMMENDED_ACTIONS.get(_etype, _DEFAULT_ACTIONS)

    _report = {
        # ── Identity ──────────────────────────────────────────────────────
        "event_id":             _eid,
        "timestamp":            _alert.get("timestamp", ""),
        "processed_at":         datetime.now(timezone.utc).isoformat() + "Z",

        # ── Step 1 output ─────────────────────────────────────────────────
        "threat_classification": _threat_class,
        "mitre_technique": {
            "id":          _mitre_id,
            "name":        _mitre_name,
            "tactic":      _mitre_tactic,
            "description": _mitre_desc,
            "reference":   f"https://attack.mitre.org/techniques/{_mitre_id.replace('.', '/').replace('/', '/')}",
        },

        # ── Step 2 output ─────────────────────────────────────────────────
        "asset_context": {
            "criticality_tier":    _asset_tier,
            "criticality_score":   _asset_cscore,
            "criticality_notes":   _asset_notes,
            "svm":                 _alert.get("svm", "N/A"),
            "node":                _alert.get("node", "N/A"),
            "source":              _alert.get("source", "UNKNOWN"),
        },
        "volume_posture":   _snap_posture,
        "blast_radius":     _blast,

        # ── Step 3 output ─────────────────────────────────────────────────
        "urgency_score":            _urgency,
        "urgency_score_breakdown":  _urgency_breakdown,
        "human_verdict":            _verdict,
        "human_reviewed_by":        _dec.get("reviewed_by", "automated_pipeline"),
        "requires_action":          _dec.get("requires_action", _urgency >= 5),

        # ── Step 4 output ─────────────────────────────────────────────────
        "recommended_actions":      _rec_actions,
        "remediation_api_calls":    _api_calls,

        # ── Supplemental alert fields ─────────────────────────────────────
        "severity":    _sev,
        "event_type":  _etype,
        "source_ip":   _alert.get("source_ip", "0.0.0.0"),
        "risk_score":  _alert.get("risk_score", 0),
        "triage":      _alert.get("triage", ""),
        "description": _alert.get("description", ""),
    }

    reactive_triage[_eid] = _report

    # ── Console output per alert ──────────────────────────────────────────
    _URGENCY_ICON = {10: "🔴", 9: "🔴", 8: "🟠", 7: "🟠", 6: "🟡", 5: "🟡", 4: "🟢", 3: "🟢"}
    _icon = _URGENCY_ICON.get(_urgency, "⚪")
    print(f"┌{'─'*(_W-2)}┐")
    print(f"│  {_icon} [{_sev:<8}] {_etype:<30} urgency={_urgency}/10{' '*(6)}│")
    print(f"│  event_id  : {_eid:<58} │")
    print(f"│  MITRE     : {_mitre_id} — {_mitre_name:<46} │")
    print(f"│  Tactic    : {_mitre_tactic:<59} │")
    print(f"│  Verdict   : {_verdict:<20}  Asset: {_asset_tier:<24} │")
    print(f"│  Blast     : {_blast['blast_scope']:<20}  RPO: {_snap_posture['recovery_point_obj']:<24} │")
    print(f"│  API calls : {len(_api_calls)} remediation steps generated{' '*32}│")
    print(f"└{'─'*(_W-2)}┘")

print()
print(f"{'═'*_W}")
print(f"  ✅ Reactive triage complete — {len(reactive_triage)} alert(s) processed")
print()

# ── Summary table ─────────────────────────────────────────────────────
_urgent_count = sum(1 for r in reactive_triage.values() if r["urgency_score"] >= 7)
_mitre_dist   = Counter(r["mitre_technique"]["tactic"] for r in reactive_triage.values())
_blast_dist   = Counter(r["blast_radius"]["blast_scope"] for r in reactive_triage.values())

print(f"  Urgency ≥ 7  : {_urgent_count}/{len(reactive_triage)} alerts require immediate action")
print(f"  MITRE Tactics: {dict(_mitre_dist)}")
print(f"  Blast Scope  : {dict(_blast_dist)}")
print()
print(f"  Top urgency alert:")
_top = max(reactive_triage.values(), key=lambda r: r["urgency_score"])
print(f"    event_id   : {_top['event_id']}")
print(f"    type       : {_top['event_type']}")
print(f"    urgency    : {_top['urgency_score']}/10")
print(f"    MITRE      : {_top['mitre_technique']['id']} — {_top['mitre_technique']['name']}")
print(f"    blast      : {_top['blast_radius']['blast_scope']}")
print(f"    api_calls  : {len(_top['remediation_api_calls'])} steps")
print(f"    top action : {_top['recommended_actions'][0]}")
print(f"{'═'*_W}")
