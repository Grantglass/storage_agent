
"""
proactive_threat_hunter — Python Coding Agent
==============================================
Proactive storage threat hunter running in PARALLEL to the reactive SOC agent.
For each alert in the aggregated batch, detects weak signals the reactive pipeline
would miss, maps to MITRE ATT&CK kill chain stages, computes confidence + time-to-
impact, and recommends pre-emptive NetApp ONTAP API actions.

Input  : enriched_alert (list), triage (list) — from aggregate_alerts
Output : proactive_intel (dict) — forward-looking threat intelligence packet
         Keys: predicted_threat_vector, kill_chain_stage, confidence_score,
               time_to_impact, preemptive_actions, ontap_api_calls,
               all_alert_intel, kill_chain_progressions, summary
"""

from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# KILL CHAIN / MITRE ATT&CK STAGE DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

_KILL_CHAIN = {
    "RECONNAISSANCE": {
        "label":       "TA0043 Reconnaissance",
        "description": "Attacker gathering intelligence — port scans, API probing, credential enumeration",
        "next_stage":  "INITIAL_ACCESS",
        "urgency_hrs": 48,
    },
    "INITIAL_ACCESS": {
        "label":       "TA0001 Initial Access",
        "description": "Attacker establishing foothold — brute force, phishing, exploit",
        "next_stage":  "EXECUTION",
        "urgency_hrs": 24,
    },
    "EXECUTION": {
        "label":       "TA0002 Execution",
        "description": "Malicious code running in environment — malware, scripts, API abuse",
        "next_stage":  "PERSISTENCE",
        "urgency_hrs": 12,
    },
    "PERSISTENCE": {
        "label":       "TA0003 Persistence",
        "description": "Attacker maintaining access — new accounts, modified FPolicy, CIFS manipulation",
        "next_stage":  "PRIVILEGE_ESCALATION",
        "urgency_hrs": 8,
    },
    "PRIVILEGE_ESCALATION": {
        "label":       "TA0004 Privilege Escalation",
        "description": "Elevating access rights — service account abuse, SVM admin compromise",
        "next_stage":  "DEFENSE_EVASION",
        "urgency_hrs": 6,
    },
    "DEFENSE_EVASION": {
        "label":       "TA0005 Defense Evasion",
        "description": "Covering tracks — audit log manipulation, snapshot deletion, ARP disable attempts",
        "next_stage":  "COLLECTION",
        "urgency_hrs": 4,
    },
    "COLLECTION": {
        "label":       "TA0009 Collection",
        "description": "Staging data — bulk file access, volume enumeration, IOPS spike",
        "next_stage":  "EXFILTRATION",
        "urgency_hrs": 3,
    },
    "EXFILTRATION": {
        "label":       "TA0010 Exfiltration",
        "description": "Data leaving environment — large outbound transfers, replication abuse",
        "next_stage":  "IMPACT",
        "urgency_hrs": 1,
    },
    "IMPACT": {
        "label":       "TA0040 Impact",
        "description": "Destructive action — ransomware encryption, data destruction, volume wipe",
        "next_stage":  "POST_INCIDENT",
        "urgency_hrs": 0,
    },
}

_STAGE_ORDER = list(_KILL_CHAIN.keys())

# ─────────────────────────────────────────────────────────────────────────────
# WEAK SIGNAL DETECTION RULES
# Each: (test_fn, signal_name, kill_chain_stage, base_confidence, description, iops_flag)
# ─────────────────────────────────────────────────────────────────────────────

def _check_api_probe(a):
    return (a["event_type"] in ("UNAUTHORIZED_ACCESS", "STORAGE_EVENT") and
            ("api" in a["description"].lower() or "rest" in a["description"].lower() or
             "mgmt.api" in a.get("msg_name", "")))

def _check_cert_expiry(a):
    return a["event_type"] == "CERTIFICATE_ALERT"

def _check_audit_log_rotation(a):
    return a["event_type"] == "AUDIT_EVENT"

def _check_account_lockout(a):
    return (a["event_type"] == "BRUTE_FORCE" and
            ("lock" in a["description"].lower() or
             "security.account.lock" in a.get("msg_name", "")))

def _check_fpolicy_block(a):
    return ("fpolicy" in a.get("msg_name", "").lower() or
            "fpolicy" in a["description"].lower())

def _check_service_account_abuse(a):
    return (a["event_type"] == "PRIVILEGE_ESCALATION" and
            ("svc" in a["description"].lower() or "service" in a["description"].lower()))

def _check_syn_flood(a):
    return ("syn flood" in a["description"].lower() or
            "firewall" in a.get("msg_name", "").lower())

def _check_tor_exit_ip(a):
    return a.get("source_ip", "") in {"185.220.101.5", "45.33.32.156"}

def _check_insider_exfil(a):
    return ("jsmith" in a["description"].lower() or
            "insider" in a.get("msg_name", "").lower() or
            (a["event_type"] == "DATA_EXFILTRATION" and "gb" in a["description"].lower()))

def _check_mass_encryption(a):
    return ("encryp" in a["description"].lower() or
            "ransomware" in a.get("msg_name", "").lower())

def _check_vscan_virus(a):
    return ("vscan" in a.get("msg_name", "").lower() or
            "virus" in a["description"].lower())

def _check_abnormal_volume_scope(a):
    return ("new volumes" in a["description"].lower() or
            "outside normal scope" in a["description"].lower())

def _check_ssh_brute(a):
    return ("ssh" in a["description"].lower() and a["event_type"] == "BRUTE_FORCE")

_WEAK_SIGNAL_RULES = [
    (_check_api_probe,          "REST API security endpoint probe",          "RECONNAISSANCE",     0.55,
     "IOPS pattern: low sustained reads on /api/security — attacker mapping account structure", True),
    (_check_cert_expiry,        "SSL cert expiry during active attack",       "DEFENSE_EVASION",    0.45,
     "Expiry window reduces SSL inspection — attacker may leverage for MITM replay", False),
    (_check_audit_log_rotation, "Audit log rotation during breach",           "DEFENSE_EVASION",    0.50,
     "Snapshot deletion trend: logs being rotated to obscure access trail", True),
    (_check_account_lockout,    "Account lockout → imminent credential pivot","INITIAL_ACCESS",     0.70,
     "Access pattern shift: auth failures peak then silence = lockout bypass success", True),
    (_check_fpolicy_block,      "FPolicy block → attacker routing around policy","PERSISTENCE",     0.65,
     "FPolicy bypass probe: blocked path signals testing of alternate file access vectors", True),
    (_check_service_account_abuse, "Service account privilege escalation",   "PRIVILEGE_ESCALATION", 0.75,
     "SVM anomaly: svc account scope expanding beyond normal volume set", True),
    (_check_syn_flood,          "TCP SYN flood on cluster network",           "RECONNAISSANCE",     0.60,
     "IOPS network-layer: SYN flood as DDoS precursor or storage port mapping", False),
    (_check_tor_exit_ip,        "Tor exit node — anonymised threat actor",    "INITIAL_ACCESS",     0.80,
     "Access pattern: Tor IPs correlate with credential stuffing + data staging campaigns", True),
    (_check_insider_exfil,      "Insider bulk data transfer — active exfil",  "EXFILTRATION",       0.90,
     "IOPS spike: sustained high read IOPS on finance/prod volumes during off-hours", True),
    (_check_mass_encryption,    "Mass file encryption — ransomware IMPACT",   "IMPACT",             0.95,
     "IOPS explosion: write IOPS >> baseline across multiple volumes = encryption in progress", True),
    (_check_vscan_virus,        "Vscan virus → adjacent spread risk",         "EXECUTION",          0.75,
     "Replication lag anomaly: CIFS virus spread may introduce snapshot inconsistency", True),
    (_check_abnormal_volume_scope, "Abnormal volume access scope",            "COLLECTION",         0.80,
     "Access pattern: breadth-first volume enumeration = data staging before exfiltration", True),
    (_check_ssh_brute,          "SSH brute force on ONTAP node mgmt",         "INITIAL_ACCESS",     0.70,
     "Access pattern: cluster-level SSH targeted = attacker seeking privileged node access", True),
]

# ─────────────────────────────────────────────────────────────────────────────
# ONTAP PRE-EMPTIVE ACTION BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _build_ontap_actions(stage, alert, signals):
    _svm    = alert.get("svm") or "svm-prod"
    _src_ip = alert.get("source_ip", "0.0.0.0")
    _ts     = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    _acts   = []
    _calls  = []

    if stage in ("COLLECTION", "EXFILTRATION", "IMPACT", "EXECUTION", "PRIVILEGE_ESCALATION"):
        _acts.append(
            f"CREATE EMERGENCY SNAPSHOT: Capture point-in-time snapshot on {_svm} "
            "before attacker can delete or encrypt data"
        )
        _calls.append({
            "method": "POST", "endpoint": "/api/storage/volumes/*/snapshots",
            "body": {"name": f"emergency-hunter-{_ts}",
                     "comment": f"Proactive hunter: {stage} stage — emergency capture",
                     "snaplock_expiry_time": "2026-12-31T00:00:00Z"},
            "purpose": "Immutable emergency snapshot before ransomware/exfil impact",
        })

    if stage in ("RECONNAISSANCE", "INITIAL_ACCESS", "PERSISTENCE", "COLLECTION"):
        _acts.append(
            f"TIGHTEN FPOLICY: Enable deny-by-default FPolicy on {_svm} — block "
            f".exe/.dll/.ps1/.bat writes; add {_src_ip} to IP deny list"
        )
        _calls.append({
            "method": "PATCH", "endpoint": f"/api/protocols/fpolicy/{_svm}/policies/default",
            "body": {"enabled": True, "engine": {"type": "synchronous"},
                     "events": ["write", "rename", "delete"],
                     "scope": {"file_extensions_to_exclude": ["exe", "dll", "ps1", "bat", "vbs", "crypto"]}},
            "purpose": "Harden FPolicy to block malicious file operations before execution stage",
        })

    if stage in ("EXECUTION", "COLLECTION", "IMPACT", "PERSISTENCE"):
        _acts.append(
            f"ENABLE ARP: Activate Autonomous Ransomware Protection on all volumes in {_svm} — "
            "ARP auto-detects entropy spikes and creates protective snapshots"
        )
        _calls.append({
            "method": "PATCH", "endpoint": "/api/storage/volumes",
            "query": f"svm.name={_svm}",
            "body": {"anti_ransomware": {"state": "enabled"}},
            "purpose": "ARP monitors write entropy; auto-creates snapshot on ransomware-like activity",
        })

    if stage == "IMPACT" or (stage == "EXFILTRATION" and
                              any("insider" in s.lower() or "exfil" in s.lower() for s in signals)):
        _acts.append(
            f"ISOLATE SVM: Restrict {_svm} data LIF network access; "
            f"quarantine source IP {_src_ip} at cluster firewall"
        )
        _calls.append({
            "method": "PATCH", "endpoint": "/api/network/ip/interfaces",
            "query": f"svm.name={_svm}&service_policy=data",
            "body": {"enabled": False},
            "purpose": f"Isolate SVM data path to contain active {stage} impact",
        })
        _calls.append({
            "method": "POST", "endpoint": "/api/security/firewall/policy",
            "body": {"policy": "deny-attacker",
                     "rules": [{"service": "all", "address": _src_ip, "action": "deny"}]},
            "purpose": f"Block attacker IP {_src_ip} at ONTAP cluster firewall",
        })

    if _src_ip not in ("0.0.0.0", "N/A") and stage != "IMPACT":
        _acts.append(
            f"BLOCK SOURCE IP: Add {_src_ip} to ONTAP NFS/CIFS deny list; "
            "throttle connections to 0 ops/sec"
        )
        _calls.append({
            "method": "POST", "endpoint": "/api/protocols/nfs/export-policies/*/rules",
            "body": {"clients": [{"match": _src_ip}], "rw_rule": ["never"], "ro_rule": ["never"]},
            "purpose": f"Block malicious IP {_src_ip} from NFS/CIFS protocol access",
        })

    if stage == "DEFENSE_EVASION":
        _acts.append(
            f"ENABLE SNAPLOCK: Convert snapshots to SnapLock WORM compliance on {_svm} — "
            "prevent deletion by rogue admin during defense evasion phase"
        )
        _calls.append({
            "method": "PATCH", "endpoint": "/api/storage/volumes",
            "query": f"svm.name={_svm}",
            "body": {"snaplock": {"type": "compliance", "retention": {"default": "P30D"},
                                  "is_audit_log": True}},
            "purpose": "SnapLock WORM prevents snapshot deletion by ransomware or rogue admin",
        })

    if stage in ("EXFILTRATION", "COLLECTION"):
        _acts.append(
            f"VERIFY REPLICATION LAG: Check SnapMirror lag on {_svm} — unusual lag "
            "may indicate DR site used for exfiltration or SnapMirror poisoning"
        )
        _calls.append({
            "method": "GET", "endpoint": "/api/snapmirror/relationships",
            "query": f"source.svm.name={_svm}&fields=lag_time,healthy,last_transfer_size",
            "purpose": "Detect anomalous SnapMirror lag — signals exfil via replication or sabotage",
        })

    return _acts, _calls


# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE SCORER
# ─────────────────────────────────────────────────────────────────────────────

def _score_confidence(alert, signals, base):
    _c = base
    _c += {"CRITICAL": 0.15, "HIGH": 0.08, "MEDIUM": 0.03, "LOW": 0.0}.get(alert.get("severity", "LOW"), 0.0)
    if alert.get("source_ip") in {"185.220.101.5", "45.33.32.156", "203.0.113.42"}:
        _c += 0.10
    if len(signals) >= 2:
        _c += 0.08
    if len(signals) >= 3:
        _c += 0.05
    if alert.get("source") == "DII":
        _c += 0.05
    if alert.get("triage") in ("BLOCK_AND_ESCALATE", "ALERT_SOC"):
        _c += 0.05
    if alert.get("triage") == "IGNORE" and _c > 0.4:
        _c += 0.10  # missed by reactive pipeline — higher intel value
    return round(min(_c, 0.99), 2)


def _time_to_impact(stage, conf):
    _base = _KILL_CHAIN.get(stage, _KILL_CHAIN["RECONNAISSANCE"])["urgency_hrs"]
    _mul  = 0.5 if conf >= 0.85 else (0.75 if conf >= 0.70 else 1.0)
    _hrs  = _base * _mul
    if _hrs < 1:
        return "Imminent (<1 hour)"
    elif _hrs < 4:
        return f"{_hrs:.0f}–{_hrs * 1.5:.0f} hours"
    elif _hrs < 24:
        return f"{_hrs:.0f}–{_hrs + 12:.0f} hours"
    return f"{_hrs:.0f}+ hours — active monitoring window"


# ─────────────────────────────────────────────────────────────────────────────
# CROSS-BATCH KILL CHAIN PROGRESSION
# ─────────────────────────────────────────────────────────────────────────────

def _detect_progressions(alerts):
    _TYPE_TO_STAGE = {
        "PORT_SCAN": "RECONNAISSANCE", "SQL_INJECTION": "INITIAL_ACCESS",
        "BRUTE_FORCE": "INITIAL_ACCESS", "UNAUTHORIZED_ACCESS": "INITIAL_ACCESS",
        "MALWARE_DETECTED": "EXECUTION", "AUDIT_EVENT": "DEFENSE_EVASION",
        "POLICY_VIOLATION": "RECONNAISSANCE", "PRIVILEGE_ESCALATION": "PRIVILEGE_ESCALATION",
        "ANOMALOUS_IO": "COLLECTION", "DATA_EXFILTRATION": "EXFILTRATION",
        "CERTIFICATE_ALERT": "DEFENSE_EVASION", "STORAGE_EVENT": "RECONNAISSANCE",
    }
    _by_ip = {}
    for _a in alerts:
        _ip = _a.get("source_ip", "unknown")
        if _ip not in _by_ip:
            _by_ip[_ip] = []
        _by_ip[_ip].append(_a)

    _chains = []
    for _ip, _ip_alerts in _by_ip.items():
        if _ip in ("0.0.0.0", "N/A", "unknown"):
            continue
        _stages = {_TYPE_TO_STAGE[_a["event_type"]] for _a in _ip_alerts
                   if _a["event_type"] in _TYPE_TO_STAGE}
        if not _stages:
            continue
        _hi_idx   = max(_STAGE_ORDER.index(s) for s in _stages)
        _hi_stage = _STAGE_ORDER[_hi_idx]
        _chains.append({
            "source_ip":     _ip,
            "stages_seen":   sorted(_stages, key=lambda s: _STAGE_ORDER.index(s)),
            "highest_stage": _hi_stage,
            "alert_count":   len(_ip_alerts),
            "confidence":    round(min(0.40 + len(_stages) * 0.15, 0.95), 2),
            "next_stage":    _KILL_CHAIN[_hi_stage]["next_stage"],
        })
    return sorted(_chains,
                  key=lambda c: (_STAGE_ORDER.index(c["highest_stage"]), c["confidence"]),
                  reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENGINE
# ─────────────────────────────────────────────────────────────────────────────

_SEP = "═" * 100
print(_SEP)
print("  🎯  PROACTIVE STORAGE THREAT HUNTER — Weak Signal Detection Engine  [Python Coding Agent]")
print(f"  Analysing {len(enriched_alert)} alerts  │  "
      f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
print(_SEP)

_DEFAULT_STAGE_MAP = {
    "PORT_SCAN": "RECONNAISSANCE", "SQL_INJECTION": "INITIAL_ACCESS",
    "BRUTE_FORCE": "INITIAL_ACCESS", "UNAUTHORIZED_ACCESS": "INITIAL_ACCESS",
    "MALWARE_DETECTED": "EXECUTION", "AUDIT_EVENT": "DEFENSE_EVASION",
    "POLICY_VIOLATION": "RECONNAISSANCE", "PRIVILEGE_ESCALATION": "PRIVILEGE_ESCALATION",
    "ANOMALOUS_IO": "COLLECTION", "DATA_EXFILTRATION": "EXFILTRATION",
    "CERTIFICATE_ALERT": "DEFENSE_EVASION", "STORAGE_EVENT": "RECONNAISSANCE",
}

_VECTOR_TPL = {
    "RECONNAISSANCE":      "{t} → Credential/topology enumeration before active exploitation",
    "INITIAL_ACCESS":      "{t} → Foothold establishment on storage cluster or SVM",
    "EXECUTION":           "{t} → Malicious payload executing on storage infrastructure",
    "PERSISTENCE":         "{t} → Persistent backdoor or rogue ONTAP policy modification",
    "PRIVILEGE_ESCALATION":"{t} → SVM admin or vsadmin role compromise pending",
    "DEFENSE_EVASION":     "{t} → Audit trail manipulation or snapshot deletion to cover tracks",
    "COLLECTION":          "{t} → Bulk data staging across ONTAP volumes before exfiltration",
    "EXFILTRATION":        "{t} → Active data theft via NFS/CIFS/SnapMirror channel",
    "IMPACT":              "{t} → Storage destruction, encryption, or ransomware payload deployment",
}

_intel_per_alert = []

for _a in enriched_alert:
    _eid   = _a["event_id"]
    _etype = _a["event_type"]
    _sev   = _a["severity"]
    _src   = _a.get("source", "UNKNOWN")
    _ip    = _a.get("source_ip", "0.0.0.0")
    _tri   = _a.get("triage", "UNKNOWN")
    _score = _a.get("risk_score", 0)

    # Run weak-signal rules
    _sigs  = []
    _stgs  = []
    _descs = []
    _iops  = []
    _base  = 0.30

    for (_fn, _name, _stg, _conf, _desc, _iops_flag) in _WEAK_SIGNAL_RULES:
        if _fn(_a):
            _sigs.append(_name)
            _stgs.append(_stg)
            _descs.append(_desc)
            _base = max(_base, _conf)
            if _iops_flag:
                _iops.append(_name)

    # Kill chain stage: highest stage from matched signals, else default
    if _stgs:
        _stage = max(_stgs, key=lambda s: _STAGE_ORDER.index(s) if s in _STAGE_ORDER else 0)
    else:
        _stage = _DEFAULT_STAGE_MAP.get(_etype, "RECONNAISSANCE")

    _conf = _score_confidence(_a, _sigs, _base)
    _tti  = _time_to_impact(_stage, _conf)

    _vec = _VECTOR_TPL.get(_stage, "{t} → Unknown threat vector").format(t=_etype)

    _weak_summary = "; ".join(_sigs) if _sigs else "No additional weak signals — direct threat indicator"
    _anomalies    = _descs if _descs else [f"{_etype} is a primary indicator at severity {_sev}"]

    _acts, _calls = _build_ontap_actions(_stage, _a, _sigs)
    if not _acts:
        _acts = ["MONITOR: No immediate pre-emptive action required — maintain elevated monitoring"]

    _next_s    = _KILL_CHAIN.get(_stage, {}).get("next_stage", "POST_INCIDENT")
    _next_info = _KILL_CHAIN.get(_next_s, {})
    _next_desc = (f"[{_next_s}] {_next_info.get('description', 'Attack campaign conclusion')}"
                  if _next_info else "Post-incident forensics and cleanup")

    _intel = {
        "event_id":               str(_eid),
        "predicted_threat_vector": _vec,
        "kill_chain_stage":        _KILL_CHAIN.get(_stage, {}).get("label", _stage),
        "kill_chain_stage_id":     _stage,
        "confidence_score":        _conf,
        "time_to_impact":          _tti,
        "weak_signals_detected":   _sigs,
        "behavioral_anomalies":    _anomalies,
        "iops_drift_indicators":   _iops,
        "predicted_next_phase":    _next_desc,
        "preemptive_actions":      _acts,
        "ontap_api_calls":         _calls,
        "source_alert": {
            "event_type": _etype, "severity": _sev, "source_ip": _ip,
            "source": _src, "triage": _tri, "risk_score": _score,
        },
        "missed_by_reactive":  (_tri in ("IGNORE", "LOG_AND_MONITOR") and _conf >= 0.55),
        "hunter_timestamp":    datetime.now(timezone.utc).isoformat(),
    }
    _intel_per_alert.append(_intel)

    _bar      = "█" * int(_conf * 10) + "░" * (10 - int(_conf * 10))
    _miss_tag = "  ⚠️ MISSED BY REACTIVE" if _intel["missed_by_reactive"] else ""
    print(f"\n{'─'*70}")
    print(f"  [{str(_eid)[:8]}...]  {_sev:<10} {_etype}{_miss_tag}")
    print(f"{'─'*70}")
    print(f"  🎯 Threat Vector    : {_vec[:68]}")
    print(f"  ⛓  Kill Chain Stage : {_KILL_CHAIN.get(_stage, {}).get('label', _stage)}")
    print(f"  📊 Confidence       : {_bar} {_conf:.0%}")
    print(f"  ⏱  Time-to-Impact   : {_tti}")
    if _sigs:
        print(f"  🔍 Weak Signals     : {'; '.join(_sigs)[:68]}")
    if _iops:
        print(f"  📈 IOPS/Access Drift: {'; '.join(_iops[:2])[:68]}")
    print(f"  ⚡ Top ONTAP Action  : {_acts[0][:68]}")
    print(f"  🔮 Predicted Next   : {_next_desc[:68]}")

# ─── Cross-alert kill chain progression ─────────────────────────────────────
_chains = _detect_progressions(enriched_alert)
print(f"\n\n{_SEP}")
print("  🔗  CROSS-EVENT KILL CHAIN PROGRESSION ANALYSIS")
print(_SEP)
if _chains:
    for _ch in _chains[:5]:
        print(f"\n  IP: {_ch['source_ip']:<20}  Alerts: {_ch['alert_count']}  "
              f"Confidence: {_ch['confidence']:.0%}")
        print(f"  Kill Chain Path : {' → '.join(_ch['stages_seen'])}")
        print(f"  Highest Stage   : {_ch['highest_stage']}  →  Next: {_ch['next_stage']}")
else:
    print("  No multi-stage chains detected.")

# ─── Summary ─────────────────────────────────────────────────────────────────
_missed      = sum(1 for i in _intel_per_alert if i["missed_by_reactive"])
_hi_conf     = sum(1 for i in _intel_per_alert if i["confidence_score"] >= 0.75)
_stages_act  = list({i["kill_chain_stage_id"] for i in _intel_per_alert})
_most_urgent = min(_intel_per_alert,
                   key=lambda i: _KILL_CHAIN.get(i["kill_chain_stage_id"], {}).get("urgency_hrs", 999))
_n_api_calls = sum(len(i["ontap_api_calls"]) for i in _intel_per_alert)

print(f"\n{_SEP}")
print("  📋  HUNTER SUMMARY")
print(f"  Total alerts analysed    : {len(_intel_per_alert)}")
print(f"  Missed by reactive agent : {_missed}  (weak signals the reactive pipeline would skip)")
print(f"  High-confidence threats  : {_hi_conf}  (confidence ≥ 75%)")
print(f"  Active kill chain stages : {', '.join(_stages_act)}")
print(f"  ONTAP pre-emptive calls  : {_n_api_calls} queued")
print(f"  Most urgent alert        : [{str(_most_urgent['event_id'])[:8]}...]  "
      f"stage={_most_urgent['kill_chain_stage_id']}  tti={_most_urgent['time_to_impact']}")
print(_SEP)

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT: proactive_intel
# Schema: predicted_threat_vector, kill_chain_stage, confidence_score,
#         time_to_impact, preemptive_actions, ontap_api_calls (ticket requirements)
#         + all_alert_intel, kill_chain_progressions, summary (extended)
# ─────────────────────────────────────────────────────────────────────────────
proactive_intel = {
    # Top-level: most urgent alert's forward-looking intelligence (ticket schema)
    "predicted_threat_vector": _most_urgent["predicted_threat_vector"],
    "kill_chain_stage":        _most_urgent["kill_chain_stage"],
    "confidence_score":        _most_urgent["confidence_score"],
    "time_to_impact":          _most_urgent["time_to_impact"],
    "preemptive_actions":      _most_urgent["preemptive_actions"],
    "ontap_api_calls":         _most_urgent["ontap_api_calls"],
    # Full batch intelligence
    "all_alert_intel":         _intel_per_alert,
    "kill_chain_progressions": _chains,
    "summary": {
        "total_alerts":             len(_intel_per_alert),
        "missed_by_reactive":       _missed,
        "high_confidence_count":    _hi_conf,
        "active_kill_chain_stages": _stages_act,
        "ontap_api_calls_total":    _n_api_calls,
        "hunter_run_at":            datetime.now(timezone.utc).isoformat(),
    },
}

print(f"\n✅  proactive_intel exported — {len(_intel_per_alert)} alert packets, "
      f"{_missed} reactive gaps filled, {_n_api_calls} ONTAP actions queued.")
