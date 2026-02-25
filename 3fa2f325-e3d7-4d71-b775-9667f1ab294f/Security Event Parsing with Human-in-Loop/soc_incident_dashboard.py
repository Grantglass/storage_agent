
# ╔══════════════════════════════════════════════════════════════════════╗
# ║         SOC INCIDENT DASHBOARD  —  Unified Threat Report            ║
# ╚══════════════════════════════════════════════════════════════════════╝

import re
import os
from collections import Counter
from datetime import datetime, timezone

# ── Colour / formatting helpers ────────────────────────────────────────
W   = "\033[0m"
RED = "\033[91m"
YEL = "\033[93m"
GRN = "\033[92m"
CYN = "\033[96m"
MAG = "\033[95m"
BLD = "\033[1m"
DIM = "\033[2m"

SEV_COLOR = {"CRITICAL": RED, "HIGH": YEL, "MEDIUM": CYN, "LOW": DIM}
TRIAGE_ICON = {
    "BLOCK_AND_ESCALATE": "🔴",
    "ALERT_SOC":          "🟠",
    "LOG_AND_MONITOR":    "🟡",
    "IGNORE":             "⚪",
}

def sev_badge(sev):
    c = SEV_COLOR.get(sev, "")
    return f"{c}{BLD}{sev:<8}{W}"

def urgency_bar(score, max_score=10):
    filled = int(round(score / max_score * 20))
    bar = "█" * filled + "░" * (20 - filled)
    color = RED if score >= 8 else YEL if score >= 5 else GRN
    return f"{color}{bar}{W} {BLD}{score}/{max_score}{W}"

def _extract_urgency(text):
    m = re.search(r"URGENCY[:\s]+(\d+)\s*/\s*10", text, re.IGNORECASE)
    return int(m.group(1)) if m else 0

def _extract_section(text, heading_pattern):
    pattern = rf"(?:\*\*{heading_pattern}\*\*|{heading_pattern})(.*?)(?=\n\s*(?:\*\*\d\.|##\s*\d\.|$))"
    m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else ""

def _parse_hunter_events(hunter_text):
    events = []
    chunks = re.split(r"EVENT\s+\[\d+\]\s+[—–-]+\s*", hunter_text)
    for chunk in chunks[1:]:
        lines = chunk.strip().splitlines()
        event_id_line = lines[0].strip() if lines else ""
        block = "\n".join(lines)
        eid_match = re.match(r"([a-f0-9\-]{36})", event_id_line)
        eid = eid_match.group(1) if eid_match else "unknown"
        def _grab(pattern, txt=block):
            m2 = re.search(pattern, txt)
            return m2.group(1).strip() if m2 else "—"
        events.append(dict(
            event_id    = eid,
            vector      = _grab(r"Predicted Threat Vector\s*:(.*)"),
            confidence  = _grab(r"Confidence Level\s*:(.*)")[:6].strip(),
            tti         = _grab(r"Time-to-Impact Estimate\s*:(.*)"),
            weak_signal = _grab(r"Weak Signal Detected\s*:(.*)"),
            preemptive  = _grab(r"Pre-emptive Action\s*:(.*)"),
        ))
    return events

def _parse_threat_chain(hunter_text):
    m = re.search(r"CROSS-EVENT THREAT CHAIN ANALYSIS\s*[═=]+\s*(.*)", hunter_text, re.DOTALL)
    return m.group(1).strip() if m else ""

# ── Wire up AI outputs ─────────────────────────────────────────────────
# triage_report   → reactive deep-triage from relay_triage_report
# hunter_output   → proactive threat hunt, loaded from file written by relay_hunter_output
_analyst_text = triage_report

# Load hunter output from file (written by relay_hunter_output block)
_hunter_file = "/tmp/hunter_output.txt"
if os.path.exists(_hunter_file):
    with open(_hunter_file) as _f:
        _hunter_text = _f.read()
else:
    _hunter_text = hunter_output   # fallback: use in-scope variable if file not available

_decision_map  = {d["event_id"]: d for d in human_decision}
_hunter_events = _parse_hunter_events(_hunter_text)
_hunter_map    = {e["event_id"]: e for e in _hunter_events}
_threat_chain  = _parse_threat_chain(_hunter_text)

_triage_urgency    = _extract_urgency(_analyst_text)
_triage_summary    = _extract_section(_analyst_text, r"4\.?\s*ANALYST SUMMARY")
_triage_rec_action = _extract_section(_analyst_text, r"2\.?\s*RECOMMENDED ACTION")

# ── Build ranked incident list ─────────────────────────────────────────
_incidents = []
for _a in enriched_alert:
    _eid = _a["event_id"]
    _d   = _decision_map.get(_eid, {})
    _h   = _hunter_map.get(_eid, {})
    _urgency = round(_a["risk_score"] / 15 * 10)
    if _d.get("reviewed_by") == "human_analyst":
        _urgency = min(10, _urgency + 1)
    if _a["event_id"] == top_alert["event_id"]:
        _urgency = max(_urgency, _triage_urgency)
    _incidents.append({
        "event_id":        _eid,
        "event_type":      _a["event_type"],
        "severity":        _a["severity"],
        "source_ip":       _a["source_ip"],
        "risk_score":      _a["risk_score"],
        "triage":          _a["triage"],
        "urgency":         _urgency,
        "verdict":         _d.get("verdict", "—"),
        "reviewed_by":     _d.get("reviewed_by", "—"),
        "requires_action": _d.get("requires_action", False),
        "hunter":          _h,
        "is_top_alert":    _a["event_id"] == top_alert["event_id"],
    })

_incidents.sort(key=lambda x: (-x["urgency"], -x["risk_score"]))

# ── Overall Threat Posture Score [0–100] ───────────────────────────────
_sev_w    = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
_sev_sum  = sum(_sev_w.get(a["severity"], 0) for a in enriched_alert)
_sev_max  = len(enriched_alert) * 10
_esc_rate = sum(1 for a in enriched_alert if a["triage"] in ("BLOCK_AND_ESCALATE","ALERT_SOC")) / len(enriched_alert)
_top_urg  = max(i["urgency"] for i in _incidents) / 10

threat_posture_score = round(
    0.40 * (_sev_sum / _sev_max * 100) +
    0.35 * (_esc_rate * 100) +
    0.25 * (_top_urg * 100)
)

if   threat_posture_score >= 70: _posture_label = f"{RED}{BLD}CRITICAL{W}"
elif threat_posture_score >= 50: _posture_label = f"{YEL}{BLD}HIGH{W}"
elif threat_posture_score >= 30: _posture_label = f"{CYN}{BLD}ELEVATED{W}"
else:                             _posture_label = f"{GRN}{BLD}NORMAL{W}"

# ══════════════════════════════════════════════════════════════════════
#  UNIFIED SOC INCIDENT DASHBOARD
# ══════════════════════════════════════════════════════════════════════
_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
print(f"\n{'═'*80}")
print(f"  {BLD}🛡  SOC INCIDENT DASHBOARD  —  Batch Report{W}")
print(f"  Generated : {DIM}{_now}{W}   |   Batch : {BLD}{len(enriched_alert)} alerts{W}")
print(f"{'═'*80}\n")

# 1. OVERALL THREAT POSTURE ────────────────────────────────────────────
print(f"{BLD}{'─'*80}{W}")
print(f"  {BLD}1.  OVERALL THREAT POSTURE{W}")
print(f"{'─'*80}")
print(f"  Score   : {urgency_bar(threat_posture_score, 100)}")
print(f"  Status  : {_posture_label}")
_esc_count = sum(1 for a in enriched_alert if a["triage"] in ("BLOCK_AND_ESCALATE","ALERT_SOC"))
print(f"  {_esc_count}/{len(enriched_alert)} alerts requiring active SOC response  |  "
      f"Peak urgency: {BLD}{max(i['urgency'] for i in _incidents)}/10{W}")
print()

# 2. RANKED INCIDENT LIST ──────────────────────────────────────────────
print(f"{BLD}{'─'*80}{W}")
print(f"  {BLD}2.  📋  RANKED INCIDENT LIST  (highest urgency first){W}")
print(f"{'─'*80}")
print(f"  {'#':<3}  {'EVENT TYPE':<22} {'SEV':<10} {'SRC IP':<18} {'TRIAGE':<22} {'URG':>4}")
print(f"  {'─'*3}  {'─'*22} {'─'*10} {'─'*18} {'─'*22} {'─'*4}")
for _rank, _inc in enumerate(_incidents, 1):
    _icon = TRIAGE_ICON.get(_inc["triage"], "•")
    _tags = ""
    if _inc["reviewed_by"] == "human_analyst": _tags += f"  {MAG}★ HUMAN-REVIEWED{W}"
    if _inc["is_top_alert"]:                   _tags += f"  {YEL}⚑ TOP ALERT{W}"
    if _inc["requires_action"]:                _tags += f"  {RED}⚠ ACTION REQUIRED{W}"
    print(
        f"  {_rank:<3}  {_inc['event_type']:<22} {sev_badge(_inc['severity']):<10} "
        f"{_inc['source_ip']:<18} {_icon} {_inc['triage']:<20} {BLD}{_inc['urgency']:>2}/10{W}"
        f"{_tags}"
    )
print()

# 3. HUMAN-REVIEWED ALERT — DEEP TRIAGE ───────────────────────────────
_hr = [i for i in _incidents if i["reviewed_by"] == "human_analyst"]
if _hr:
    _hi = _hr[0]
    print(f"{BLD}{'─'*80}{W}")
    print(f"  {MAG}{BLD}3.  ★  HUMAN-REVIEWED ALERT  —  AI Deep-Triage Report{W}")
    print(f"{'─'*80}")
    print(f"  Event ID   : {DIM}{_hi['event_id']}{W}")
    print(f"  Event Type : {BLD}{_hi['event_type']}{W}  |  Severity: {sev_badge(_hi['severity'])}")
    print(f"  Source IP  : {_hi['source_ip']}")
    print(f"  Verdict    : {RED}{BLD}{_hi['verdict']}{W}  |  "
          f"Requires Action: {RED if _hi['requires_action'] else GRN}{BLD}{_hi['requires_action']}{W}")
    print(f"\n  {BLD}AI Urgency Score:{W}")
    print(f"  {urgency_bar(_triage_urgency)}")
    if _triage_summary:
        print(f"\n  {BLD}Executive Summary:{W}")
        for _line in _triage_summary.splitlines():
            if _line.strip():
                print(f"    {DIM}{_line.strip()}{W}")
    if _triage_rec_action:
        print(f"\n  {BLD}Recommended Actions:{W}")
        for _line in _triage_rec_action.splitlines()[:14]:
            if _line.strip():
                print(f"    {_line.strip()}")
    print()

# 4. PROACTIVE RISK WATCHLIST ──────────────────────────────────────────
print(f"{BLD}{'─'*80}{W}")
print(f"  {CYN}{BLD}4.  🔭  PROACTIVE RISK WATCHLIST{W}")
print(f"{'─'*80}")
_watchlist = [
    i for i in _incidents
    if i["hunter"] and (
        "HIGH" in i["hunter"].get("confidence","") or
        (i["hunter"].get("weak_signal","None") and "None" not in i["hunter"].get("weak_signal","None"))
    )
]
if not _watchlist:
    _watchlist = [i for i in _incidents if i["hunter"]][:4]

for _w in _watchlist[:6]:
    _h = _w["hunter"]
    if not _h:
        continue
    _conf_c = RED if "HIGH" in _h.get("confidence","") else YEL if "MED" in _h.get("confidence","") else DIM
    print(f"  {BLD}{_w['event_type']:<22}{W}  {DIM}[{_w['event_id'][:18]}…]{W}  urgency={BLD}{_w['urgency']}/10{W}")
    print(f"    🎯 Vector         : {_h.get('vector','—')[:78]}")
    print(f"    📊 Confidence     : {_conf_c}{_h.get('confidence','—')[:6]}{W}")
    print(f"    ⏱  Time-to-Impact : {_h.get('tti','—')[:60]}")
    _ws = _h.get("weak_signal","")
    if _ws and "None" not in _ws:
        print(f"    🔍 Weak Signal    : {DIM}{_ws[:78]}{W}")
    print()

# 5. CROSS-EVENT THREAT CHAIN ─────────────────────────────────────────
if _threat_chain:
    print(f"{BLD}{'─'*80}{W}")
    print(f"  {RED}{BLD}5.  🔗  CROSS-EVENT THREAT CHAIN ANALYSIS{W}")
    print(f"{'─'*80}")
    for _line in _threat_chain.splitlines()[:16]:
        if _line.strip():
            print(f"  {_line.strip()}")
    print()

# 6. BATCH STATISTICS ──────────────────────────────────────────────────
print(f"{BLD}{'─'*80}{W}")
print(f"  {BLD}6.  📊  BATCH STATISTICS{W}")
print(f"{'─'*80}")
_tc = Counter(a["triage"] for a in enriched_alert)
_sc = Counter(a["severity"] for a in enriched_alert)
_triage_rows = sorted(_tc.items(), key=lambda x: -x[1])
_sev_rows    = [(s, _sc.get(s,0)) for s in ["CRITICAL","HIGH","MEDIUM","LOW"] if _sc.get(s,0)]
print(f"  {'TRIAGE BREAKDOWN':<36}  {'SEVERITY BREAKDOWN'}")
print(f"  {'─'*34}  {'─'*28}")
for _i in range(max(len(_triage_rows), len(_sev_rows))):
    _t  = f"{'█'*_triage_rows[_i][1]}  {_triage_rows[_i][0]} ({_triage_rows[_i][1]})" if _i < len(_triage_rows) else ""
    _sc_str = ""
    if _i < len(_sev_rows):
        _sl, _sn = _sev_rows[_i]
        _sc_str = f"{SEV_COLOR.get(_sl,'')}{'█'*_sn}{W}  {_sl} ({_sn})"
    print(f"  {_t:<36}  {_sc_str}")
print()

print(f"{'═'*80}")
print(f"  {BLD}🏁  END OF SOC REPORT{W}  |  Threat Posture: {_posture_label}  |  "
      f"Score: {BLD}{threat_posture_score}/100{W}")
print(f"{'═'*80}\n")

# Expose structured outputs
soc_threat_posture_score = threat_posture_score
soc_ranked_incidents     = _incidents
