
# ══════════════════════════════════════════════════════════════════════════════
# HUMAN-IN-THE-LOOP GATE  —  SOC Analyst Decision Engine
# ══════════════════════════════════════════════════════════════════════════════
#
# Priority selection rule (per ticket):
#   → Highest-priority alert = CRITICAL severity from ONTAP EMS **or** DII.
#   → If no CRITICAL exists, fall back to the highest risk_score overall.
#   → In case of tie on CRITICAL, prefer DII source (higher-fidelity detection).
#
# Outputs:
#   human_decision      dict  — structured SOC verdict for the ONE top-priority alert
#   pass_through_decisions  list — PASS_THROUGH records for all other alerts
#
# human_decision schema:
#   verdict              : ESCALATE | INVESTIGATE | DISMISS
#   reasoning            : why this verdict was chosen
#   analyst_notes        : rich context dict (event details, recommended_next_step,
#                          estimated_time_to_respond, priority_reason, alert_detail)
#   event_id             : str
#   severity             : str
#   risk_score           : int
#   triage               : str
#   source               : str  (ONTAP_EMS | DII | SIMULATED)
#   reviewed_by          : "human_analyst"
#   reviewed_at          : ISO-8601 timestamp
#   requires_action      : bool
# ══════════════════════════════════════════════════════════════════════════════

from datetime import datetime

# ─── Severity ordering for comparison ───────────────────────────────────────
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def _alert_priority_key(a):
    """Primary: CRITICAL severity (bonus weight). Secondary: raw risk_score."""
    sev_bonus = 1000 if a["severity"] == "CRITICAL" else 0
    # DII CRITICAL gets slight edge over ONTAP CRITICAL for same score (higher fidelity)
    src_bonus = 1 if (a["severity"] == "CRITICAL" and a.get("source", "") == "DII") else 0
    return sev_bonus + a["risk_score"] + src_bonus

# ─── Identify the single highest-priority alert ──────────────────────────────
_top_alert = max(enriched_alert, key=_alert_priority_key)

# ─── Determine WHY this alert is top priority ────────────────────────────────
_is_critical = _top_alert["severity"] == "CRITICAL"
_src         = _top_alert.get("source", "UNKNOWN")
_score       = _top_alert["risk_score"]
_sev         = _top_alert["severity"]
_tri         = _top_alert["triage"]
_etype       = _top_alert["event_type"]
_src_ip      = _top_alert["source_ip"]
_eid         = _top_alert["event_id"]

if _is_critical:
    _priority_reason = (
        f"CRITICAL severity alert from {_src} — highest priority class. "
        f"Automatic human escalation gate triggered regardless of risk score."
    )
elif _score >= 12:
    _priority_reason = (
        f"No CRITICAL severity alerts present. Selected by highest risk_score={_score}/15 "
        f"(severity={_sev}, triage={_tri})."
    )
else:
    _priority_reason = (
        f"No CRITICAL severity alerts present. Highest risk_score={_score}/15 "
        f"selected for mandatory review (severity={_sev})."
    )

# ─── SOC Analyst Verdict Logic ───────────────────────────────────────────────
# Verdict decision matrix (simulates analyst judgment):
#   ESCALATE   → CRITICAL severity OR risk_score ≥ 12 OR triage is BLOCK_AND_ESCALATE
#   INVESTIGATE→ HIGH severity with risk_score ≥ 7   OR triage is ALERT_SOC
#   DISMISS    → Everything else (low evidence, likely noise)

_ESCALATE_EVENT_TYPES = {
    "RANSOMWARE", "DATA_EXFILTRATION", "MALWARE_DETECTED",
    "BRUTE_FORCE", "PRIVILEGE_ESCALATION", "SQL_INJECTION"
}

if _sev == "CRITICAL" or _score >= 12 or _tri == "BLOCK_AND_ESCALATE":
    _verdict = "ESCALATE"

    _reasoning = (
        f"Alert [{_eid}] meets immediate escalation criteria: "
        f"severity={_sev}, risk_score={_score}/15, triage='{_tri}', "
        f"event_type={_etype}, source_ip={_src_ip}, origin={_src}. "
    )
    if _sev == "CRITICAL":
        _reasoning += (
            "CRITICAL severity from a high-fidelity detection system demands "
            "zero-delay escalation to Incident Response (IR) team. "
        )
    if _score >= 12:
        _reasoning += (
            f"Risk score {_score} exceeds ESCALATE threshold (≥12). "
        )
    if _etype in _ESCALATE_EVENT_TYPES:
        _reasoning += (
            f"Event type '{_etype}' is a known high-impact threat category. "
        )
    _reasoning += "Analyst mandates immediate IR hand-off."

    _next_step = (
        "1. Isolate affected host/SVM immediately via NetApp ONTAP quarantine API. "
        "2. Open Priority-1 incident ticket and assign to Incident Response on-call. "
        "3. Collect forensic snapshot of affected volume/node. "
        "4. Notify CISO and Security leadership within 15 minutes. "
        "5. Begin containment runbook: block source IP at perimeter firewall."
    )
    _eta = "5 minutes"

elif _sev == "HIGH" or _score >= 7 or _tri == "ALERT_SOC":
    _verdict = "INVESTIGATE"

    _reasoning = (
        f"Alert [{_eid}] warrants deeper investigation: "
        f"severity={_sev}, risk_score={_score}/15, triage='{_tri}', "
        f"event_type={_etype}, source_ip={_src_ip}, origin={_src}. "
        "Elevated indicators present but insufficient confirmation for full escalation. "
        "Assigning to SOC analyst for correlation and context enrichment."
    )
    _next_step = (
        "1. Query SIEM for last 24h activity from source IP. "
        "2. Check threat intel feeds (VirusTotal, AbuseIPDB) for IP reputation. "
        "3. Review ONTAP audit logs for associated SVM/volume access patterns. "
        "4. Correlate with DII Workload Security behavior anomalies. "
        "5. Update incident ticket with findings within 30 minutes."
    )
    _eta = "30 minutes"

else:
    _verdict = "DISMISS"

    _reasoning = (
        f"Alert [{_eid}] does not meet escalation or investigation thresholds: "
        f"severity={_sev}, risk_score={_score}/15, triage='{_tri}', "
        f"event_type={_etype}, source_ip={_src_ip}, origin={_src}. "
        "Insufficient evidence of active threat. Logging for baseline analytics "
        "and dismissing to prevent alert fatigue."
    )
    _next_step = (
        "1. Log event to SIEM for baseline anomaly detection. "
        "2. No active response required. "
        "3. Flag IP for 7-day passive monitoring. "
        "4. Review in weekly threat summary report."
    )
    _eta = "0 minutes (no analyst time required)"

# ─── Construct human_decision output dict ────────────────────────────────────
human_decision = {
    "event_id":         _eid,
    "reviewed_by":      "human_analyst",
    "verdict":          _verdict,
    "reasoning":        _reasoning,
    "analyst_notes": {
        "priority_reason":          _priority_reason,
        "recommended_next_step":    _next_step,
        "estimated_time_to_respond": _eta,
        "alert_detail": {
            "event_type":   _etype,
            "severity":     _sev,
            "source":       _src,
            "source_ip":    _src_ip,
            "risk_score":   _score,
            "triage":       _tri,
            "description":  _top_alert.get("description", ""),
            "timestamp":    _top_alert.get("timestamp", ""),
            "node":         _top_alert.get("node", "N/A"),
            "svm":          _top_alert.get("svm", "N/A"),
        },
    },
    "severity":         _sev,
    "risk_score":       _score,
    "triage":           _tri,
    "source":           _src,
    "reviewed_at":      datetime.utcnow().isoformat() + "Z",
    "requires_action":  _verdict != "DISMISS",
}

# ─── All other alerts → automatic PASS_THROUGH ───────────────────────────────
pass_through_decisions = [
    {
        "event_id":         a["event_id"],
        "reviewed_by":      "automated_pipeline",
        "verdict":          "PASS_THROUGH",
        "reasoning": (
            f"Alert [{a['event_id']}] (severity={a['severity']}, "
            f"risk_score={a['risk_score']}, source={a.get('source','?')}) "
            "not selected for human review — processed automatically per triage policy."
        ),
        "analyst_notes": {
            "priority_reason":          "Lower priority than top alert; automated handling.",
            "recommended_next_step":    "Continue automated pipeline processing.",
            "estimated_time_to_respond": "0 minutes (automated)",
            "alert_detail": {
                "event_type": a["event_type"],
                "severity":   a["severity"],
                "source":     a.get("source", "UNKNOWN"),
                "source_ip":  a["source_ip"],
                "risk_score": a["risk_score"],
                "triage":     a["triage"],
            },
        },
        "severity":         a["severity"],
        "risk_score":       a["risk_score"],
        "triage":           a["triage"],
        "source":           a.get("source", "UNKNOWN"),
        "reviewed_at":      datetime.utcnow().isoformat() + "Z",
        "requires_action":  False,
    }
    for a in enriched_alert
    if a["event_id"] != _eid
]

# ─── Console Output — SOC Analyst Workstation View ───────────────────────────
_W = 70
print("═" * _W)
print("  👁  HUMAN-IN-THE-LOOP GATE  —  SOC Analyst Decision Engine")
print("═" * _W)
print(f"  Total alerts received   : {len(enriched_alert)}")
print(f"  Human-reviewed          : 1")
print(f"  Automated pass-through  : {len(pass_through_decisions)}")
print()

_VERDICT_ICON = {"ESCALATE": "🔴", "INVESTIGATE": "🟡", "DISMISS": "⚪"}
print(f"┌{'─'*(_W-2)}┐")
print(f"│  {_VERDICT_ICON.get(_verdict,'❓')} VERDICT: {_verdict:<55} │")
print(f"├{'─'*(_W-2)}┤")
print(f"│  Event ID  : {_eid:<53} │")
print(f"│  Source    : {_src:<53} │")
print(f"│  Severity  : {_sev:<53} │")
print(f"│  Risk Score: {str(_score) + '/15':<53} │")
print(f"│  Event Type: {_etype:<53} │")
print(f"│  Source IP : {_src_ip:<53} │")
print(f"│  Triage    : {_tri:<53} │")
print(f"│  ETA       : {_eta:<53} │")
print(f"├{'─'*(_W-2)}┤")
print(f"│  Priority Reason:{'':>51}│")
_words = _priority_reason.split()
_line = "│    "
for _w in _words:
    if len(_line) + len(_w) + 1 > _W - 1:
        print(f"{_line:<{_W-1}}│")
        _line = "│    " + _w
    else:
        _line += (" " if _line != "│    " else "") + _w
if _line != "│    ":
    print(f"{_line:<{_W-1}}│")
print(f"├{'─'*(_W-2)}┤")
print(f"│  Reasoning:{'':>57}│")
_words = _reasoning.split()
_line = "│    "
for _w in _words:
    if len(_line) + len(_w) + 1 > _W - 1:
        print(f"{_line:<{_W-1}}│")
        _line = "│    " + _w
    else:
        _line += (" " if _line != "│    " else "") + _w
if _line != "│    ":
    print(f"{_line:<{_W-1}}│")
print(f"├{'─'*(_W-2)}┤")
print(f"│  Next Steps:{'':>56}│")
for _step in _next_step.split(". "):
    _step = _step.strip().rstrip(".")
    if not _step:
        continue
    _words = _step.split()
    _line = "│    "
    for _w in _words:
        if len(_line) + len(_w) + 1 > _W - 1:
            print(f"{_line:<{_W-1}}│")
            _line = "│      " + _w
        else:
            _line += (" " if _line != "│    " else "") + _w
    if _line not in ("│    ", "│      "):
        print(f"{_line:<{_W-1}}│")
print(f"└{'─'*(_W-2)}┘")

print()
print(f"⚡ AUTO PASS-THROUGH ({len(pass_through_decisions)} alerts):")
for _d in sorted(pass_through_decisions, key=lambda x: -x["risk_score"]):
    _icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(_d["severity"], "⚪")
    print(f"   {_icon} [{_d['severity']:<8}] risk={_d['risk_score']:>2}  "
          f"src={_d['source']:<12} event_id={_d['event_id']}  → PASS_THROUGH")

print()
print(f"✅ human_decision exported — verdict='{_verdict}', requires_action={human_decision['requires_action']}")
