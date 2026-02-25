
# Each parallel slice receives one `storage_alert` dict from the spread() upstream.
# Unified schema: event_id, source, timestamp, severity, event_type,
#                 source_ip, description, raw_log, node, svm, msg_name

from datetime import datetime

# --- Risk scoring ---
SEVERITY_SCORE = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 10}

# High-risk event types that warrant elevated scoring
HIGH_RISK_EVENT_TYPES = {
    "MALWARE_DETECTED",
    "DATA_EXFILTRATION",
    "BRUTE_FORCE",
    "RANSOMWARE",
}
MEDIUM_RISK_EVENT_TYPES = {
    "PRIVILEGE_ESCALATION",
    "UNAUTHORIZED_ACCESS",
    "POLICY_VIOLATION",
    "ANOMALOUS_IO",
}

# Known malicious / Tor-exit / attack source IPs
RISKY_IPS = {
    "185.220.101.5",   # Tor exit node
    "45.33.32.156",    # Known scanner
    "203.0.113.42",    # TEST-NET — suspicious in prod
}

severity_score     = SEVERITY_SCORE.get(storage_alert["severity"], 0)
ip_risk_bonus      = 5 if storage_alert["source_ip"] in RISKY_IPS else 0
event_type_bonus   = 3 if storage_alert["event_type"] in HIGH_RISK_EVENT_TYPES else (
                     1 if storage_alert["event_type"] in MEDIUM_RISK_EVENT_TYPES else 0
                 )
# DII Workload Security events get an extra weight (high-fidelity detections)
source_bonus       = 2 if storage_alert.get("source") == "DII" and storage_alert["severity"] in ("CRITICAL", "HIGH") else 0

risk_score = severity_score + ip_risk_bonus + event_type_bonus + source_bonus

# --- Triage decision ---
if risk_score >= 14:
    triage = "BLOCK_AND_ESCALATE"
elif risk_score >= 8:
    triage = "ALERT_SOC"
elif risk_score >= 3:
    triage = "LOG_AND_MONITOR"
else:
    triage = "IGNORE"

# --- Enriched alert payload ---
enriched_alert = {
    **storage_alert,
    "risk_score":   risk_score,
    "triage":       triage,
    "processed_at": datetime.utcnow().isoformat() + "Z",
}

# Keep `alert` alias for downstream blocks that reference it by that name
alert = enriched_alert

_src_tag = f"[{storage_alert.get('source','?')}]"
print(f"🔒 {_src_tag} [{storage_alert['severity']}] {storage_alert['event_type']} | {storage_alert['source_ip']}")
print(f"   event_id   : {storage_alert['event_id']}")
if storage_alert.get("node"):
    print(f"   node/svm   : {storage_alert['node']} / {storage_alert.get('svm','')}")
print(f"   description: {storage_alert['description'][:80]}")
print(f"   risk_score : {risk_score}  (sev={severity_score} ip={ip_risk_bonus} type={event_type_bonus} src={source_bonus})  →  triage: {triage}")
print(f"   processed  : {enriched_alert['processed_at']}")
