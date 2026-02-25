
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║   🛡  UNIFIED SOC INCIDENT DASHBOARD  —  NetApp Storage Threat Report       ║
# ║   Fuses reactive_triage + proactive_intel into a single prioritised report  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# Inputs  (from upstream blocks):
#   reactive_triage  — dict[event_id → triage_report_dict]  (reactive_soc_analyst)
#   proactive_intel  — dict with keys all_alert_intel, kill_chain_progressions, etc.
#                      (relay_hunter_output via proactive_threat_hunter)
#
# Dashboard sections:
#   1. Overall threat posture score   (weighted average of urgency scores)
#   2. Ranked incident table          (sorted by urgency, full MITRE/blast/verdict)
#   3. Proactive risk watchlist       (confidence, TTI, pre-emptive action)
#   4. Attack chain correlation       (multi-stage campaigns by source IP / SVM)
#   5. Remediation action summary     (consolidated ONTAP/DII API calls)
# ──────────────────────────────────────────────────────────────────────────────

from collections import defaultdict, Counter
from datetime import datetime, timezone

_W   = 90   # console width
_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

# ─────────────────────────────────────────────────────────────────────────────
# 0. COLOUR / BADGE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

_RST = "\033[0m"
_RED = "\033[91m"
_YEL = "\033[93m"
_GRN = "\033[92m"
_CYN = "\033[96m"
_MAG = "\033[95m"
_BLU = "\033[94m"
_BLD = "\033[1m"
_DIM = "\033[2m"

_SEV_C  = {"CRITICAL": _RED, "HIGH": _YEL, "MEDIUM": _CYN, "LOW": _DIM, "INFO": _DIM}
_URG_IC = {10: "🔴", 9: "🔴", 8: "🟠", 7: "🟠", 6: "🟡", 5: "🟡", 4: "🟢", 3: "🟢", 2: "⚪", 1: "⚪"}


def _sev_badge(s):
    return f"{_SEV_C.get(s, '')}{_BLD}{s:<8}{_RST}"


def _urgency_bar(v, mx=10):
    _f = int(round(v / mx * 20))
    _b = "█" * _f + "░" * (20 - _f)
    _c = _RED if v >= 8 else (_YEL if v >= 5 else _GRN)
    return f"{_c}{_b}{_RST} {_BLD}{v}/{mx}{_RST}"


def _posture_bar(v, mx=10):
    _f = int(round(v / mx * 30))
    _b = "█" * _f + "░" * (30 - _f)
    _c = _RED if v >= 7.5 else (_YEL if v >= 5.5 else (_CYN if v >= 3.5 else _GRN))
    return f"{_c}{_b}{_RST} {_BLD}{v:.1f}/{mx}{_RST}"


def _conf_badge(c):
    _pct = int(c * 100)
    _c = _RED if _pct >= 80 else (_YEL if _pct >= 60 else _DIM)
    return f"{_c}{_pct}%{_RST}"

# ─────────────────────────────────────────────────────────────────────────────
# 1. OVERALL THREAT POSTURE SCORE
#    Weighted average of urgency scores across all triage reports.
#    Weights: urgency_score(40%) + requires_action(20%) + blast_scope(20%) +
#             human_verdict(20%)
# ─────────────────────────────────────────────────────────────────────────────

_BLAST_WEIGHT  = {"CLUSTER-WIDE": 10, "SVM-WIDE": 7, "VOLUME-LEVEL": 4, "LOCAL": 2}
_VERDICT_BOOST = {"ESCALATE": 1.5, "INVESTIGATE": 1.0, "PASS_THROUGH": 0.5, "DISMISS": 0.0}

_triage_list  = list(reactive_triage.values())
_n            = len(_triage_list)

if _n == 0:
    _posture = 0.0
else:
    _urgency_scores     = [r["urgency_score"]                                      for r in _triage_list]
    _requires_action    = [10.0 if r.get("requires_action") else 0.0               for r in _triage_list]
    _blast_scores       = [_BLAST_WEIGHT.get(r["blast_radius"]["blast_scope"], 2)   for r in _triage_list]
    _verdict_scores     = [_VERDICT_BOOST.get(r.get("human_verdict","PASS_THROUGH"), 0.5) * 10 / 1.5
                           for r in _triage_list]

    _raw_posture = (
        0.40 * (sum(_urgency_scores)  / _n) +
        0.20 * (sum(_requires_action) / _n) +
        0.20 * (sum(_blast_scores)    / _n) +
        0.20 * (sum(_verdict_scores)  / _n)
    )
    _posture = round(min(10.0, max(0.0, _raw_posture)), 2)

_posture_label = (
    f"{_RED}{_BLD}CRITICAL{_RST}"    if _posture >= 7.5 else
    f"{_YEL}{_BLD}HIGH{_RST}"        if _posture >= 5.5 else
    f"{_CYN}{_BLD}ELEVATED{_RST}"    if _posture >= 3.5 else
    f"{_GRN}{_BLD}NORMAL{_RST}"
)

# ─────────────────────────────────────────────────────────────────────────────
# 2. BUILD RANKED INCIDENT TABLE
# ─────────────────────────────────────────────────────────────────────────────

_ranked = sorted(_triage_list, key=lambda r: (-r["urgency_score"], -r["risk_score"]))

# ─────────────────────────────────────────────────────────────────────────────
# 3. PROACTIVE RISK WATCHLIST
#    From proactive_intel.all_alert_intel — ranked by confidence, then TTI urgency
# ─────────────────────────────────────────────────────────────────────────────

_all_intel   = proactive_intel.get("all_alert_intel", [])
_progressions = proactive_intel.get("kill_chain_progressions", [])

_STAGE_ORDER_TTI = {
    "IMPACT": 0, "EXFILTRATION": 1, "COLLECTION": 2, "DEFENSE_EVASION": 3,
    "PRIVILEGE_ESCALATION": 4, "PERSISTENCE": 5, "EXECUTION": 6,
    "INITIAL_ACCESS": 7, "RECONNAISSANCE": 8,
}

def _tti_sort_key(intel_item):
    _s = intel_item.get("kill_chain_stage_id", "RECONNAISSANCE")
    return (_STAGE_ORDER_TTI.get(_s, 9), -intel_item.get("confidence_score", 0))

_watchlist = sorted(_all_intel, key=_tti_sort_key)

# ─────────────────────────────────────────────────────────────────────────────
# 4. ATTACK CHAIN CORRELATION
#    Group by source_ip, then by svm to find multi-stage campaigns
# ─────────────────────────────────────────────────────────────────────────────

_by_ip  = defaultdict(list)
_by_svm = defaultdict(list)

for _r in _triage_list:
    _ip  = _r.get("source_ip", "unknown")
    _svm = _r["asset_context"].get("svm", "N/A")
    if _ip and _ip not in ("0.0.0.0", "unknown"):
        _by_ip[_ip].append(_r)
    if _svm and _svm not in ("N/A", "unknown"):
        _by_svm[_svm].append(_r)

# Multi-stage: IPs with >1 event are campaigns
_campaigns = {
    _ip: _evts for _ip, _evts in _by_ip.items() if len(_evts) >= 1
}
# Sort campaigns: most events + highest urgency first
_sorted_campaigns = sorted(
    _campaigns.items(),
    key=lambda kv: (-len(kv[1]), -max(e["urgency_score"] for e in kv[1]))
)

# Kill-chain progressions from proactive hunter (already computed)
_chain_by_ip = {c["source_ip"]: c for c in _progressions}

# ─────────────────────────────────────────────────────────────────────────────
# 5. REMEDIATION ACTION SUMMARY
#    Consolidate all ONTAP/DII API calls de-duplicated by action name
# ─────────────────────────────────────────────────────────────────────────────

_seen_actions  = set()
_deduped_calls = []   # list of (urgency, action_dict, event_id)

for _r in _ranked:
    _eid = _r["event_id"]
    for _call in _r.get("remediation_api_calls", []):
        _key = (_call.get("action", ""), _call.get("endpoint", "")[:50])
        if _key not in _seen_actions:
            _seen_actions.add(_key)
            _deduped_calls.append((_r["urgency_score"], _call, _eid))

# Sort by urgency descending then priority ascending
_deduped_calls.sort(key=lambda x: (-x[0], x[1].get("priority", 99)))

# Also add proactive pre-emptive ONTAP calls from hunter
_proactive_calls = proactive_intel.get("ontap_api_calls", [])

# ═════════════════════════════════════════════════════════════════════════════
# PRINT DASHBOARD
# ═════════════════════════════════════════════════════════════════════════════

print(f"\n{'═'*_W}")
print(f"  {_BLD}🛡  UNIFIED SOC INCIDENT DASHBOARD  —  NetApp Storage Threat Report{_RST}")
print(f"  Generated  : {_DIM}{_now}{_RST}  │  Alerts: {_BLD}{_n}{_RST}")
print(f"{'═'*_W}\n")

# ── SECTION 1: OVERALL THREAT POSTURE ────────────────────────────────────────
print(f"{_BLD}{'─'*_W}{_RST}")
print(f"  {_BLD}① OVERALL THREAT POSTURE SCORE{_RST}")
print(f"{'─'*_W}")
print(f"  Posture   : {_posture_bar(_posture)}")
print(f"  Status    : {_posture_label}")
_req_action_count = sum(1 for r in _triage_list if r.get("requires_action"))
_escalate_count   = sum(1 for r in _triage_list if r.get("human_verdict") == "ESCALATE")
_avg_blast        = Counter(r["blast_radius"]["blast_scope"] for r in _triage_list)
print(f"  Alerts    : {_n} total  │  {_req_action_count} require action  │  {_escalate_count} ESCALATE verdict")
print(f"  Blast     : {dict(_avg_blast)}")

# Score breakdown
if _n:
    print(f"  Score formula: urgency_avg×0.40 ({sum(_urgency_scores)/_n:.2f}) + "
          f"action×0.20 ({sum(_requires_action)/_n:.2f}) + "
          f"blast×0.20 ({sum(_blast_scores)/_n:.2f}) + "
          f"verdict×0.20 ({sum(_verdict_scores)/_n:.2f}) → {_posture:.2f}/10")
print()

# ── SECTION 2: RANKED INCIDENT TABLE ─────────────────────────────────────────
print(f"{_BLD}{'─'*_W}{_RST}")
print(f"  {_BLD}② RANKED INCIDENT TABLE  (highest urgency → lowest){_RST}")
print(f"{'─'*_W}")
_HDR = (f"  {'#':<3}  {'EVENT TYPE':<22}  {'SEV':<9}  {'SOURCE IP':<18}  "
        f"{'MITRE ID':<8}  {'BLAST':<12}  {'VERDICT':<12}  {'URG':>5}  {'HR?'}")
print(_HDR)
print(f"  {'─'*3}  {'─'*22}  {'─'*9}  {'─'*18}  {'─'*8}  {'─'*12}  {'─'*12}  {'─'*5}  {'─'*3}")

for _rank, _r in enumerate(_ranked, 1):
    _mid   = _r["mitre_technique"]["id"]
    _blast = _r["blast_radius"]["blast_scope"]
    _verd  = _r.get("human_verdict", "—")[:12]
    _urg   = _r["urgency_score"]
    _icon  = _URG_IC.get(_urg, "⚪")
    _hr    = f"{_MAG}✓{_RST}" if _r.get("human_reviewed_by") == "human_analyst" else "—"
    _sev   = _r["severity"]
    _sev_c = _SEV_C.get(_sev, "")
    _ra    = f" {_RED}⚠{_RST}" if _r.get("requires_action") else ""

    print(f"  {_rank:<3}  {_r['event_type']:<22}  "
          f"{_sev_c}{_sev:<8}{_RST}   "
          f"{_r['source_ip']:<18}  "
          f"{_mid:<8}  {_blast:<12}  {_verd:<12}  "
          f"{_icon}{_BLD}{_urg:>2}/10{_RST}  {_hr}{_ra}")

print()
print(f"  {_DIM}Top recommended action for highest-urgency alert:{_RST}")
if _ranked:
    _top = _ranked[0]
    _top_action = _top["recommended_actions"][0] if _top.get("recommended_actions") else "—"
    print(f"    {_RED}{_BLD}[{_top['event_type']} | urgency={_top['urgency_score']}/10]{_RST}  {_top_action}")
print()

# ── SECTION 3: PROACTIVE RISK WATCHLIST ──────────────────────────────────────
print(f"{_BLD}{'─'*_W}{_RST}")
print(f"  {_BLD}③ PROACTIVE RISK WATCHLIST  (by kill-chain stage × confidence){_RST}")
print(f"{'─'*_W}")
print(f"  {_DIM}{'#':<3}  {'EVENT TYPE':<22}  {'KILL CHAIN STAGE':<32}  {'CONF':>5}  {'TTI':<22}  PRE-EMPTIVE ACTION{_RST}")
print(f"  {'─'*3}  {'─'*22}  {'─'*32}  {'─'*5}  {'─'*22}  {'─'*36}")

for _wi, _w in enumerate(_watchlist[:10], 1):
    _stage = _w.get("kill_chain_stage", "—")[:32]
    _conf  = _w.get("confidence_score", 0)
    _tti   = _w.get("time_to_impact", "—")[:22]
    _etype = _w["source_alert"]["event_type"]
    _act   = (_w.get("preemptive_actions") or ["—"])[0][:36]
    _miss  = f"  {_RED}★ MISSED{_RST}" if _w.get("missed_by_reactive") else ""
    print(f"  {_wi:<3}  {_etype:<22}  {_stage:<32}  {_conf_badge(_conf):>5}  {_tti:<22}  {_act}{_miss}")

print()
print(f"  {_DIM}Proactive summary — Total alerts: {proactive_intel['summary']['total_alerts']} │ "
      f"Reactive gaps: {proactive_intel['summary']['missed_by_reactive']} │ "
      f"High confidence (≥75%): {proactive_intel['summary']['high_confidence_count']} │ "
      f"Active kill-chain stages: {', '.join(proactive_intel['summary']['active_kill_chain_stages'])}{_RST}")
print()

# ── SECTION 4: ATTACK CHAIN CORRELATION ──────────────────────────────────────
print(f"{_BLD}{'─'*_W}{_RST}")
print(f"  {_BLD}④ ATTACK CHAIN CORRELATION  (multi-stage campaigns by source IP){_RST}")
print(f"{'─'*_W}")

if not _sorted_campaigns:
    print(f"  {_DIM}No correlated campaigns detected.{_RST}")
else:
    for _ip, _evts in _sorted_campaigns[:8]:
        _chain = _chain_by_ip.get(_ip)
        _event_types = " → ".join(sorted({e["event_type"] for e in _evts},
                                         key=lambda t: -max(e["urgency_score"]
                                                             for e in _evts
                                                             if e["event_type"] == t)))
        _max_urg = max(e["urgency_score"] for e in _evts)
        _icon    = _URG_IC.get(_max_urg, "⚪")
        print(f"\n  {_icon} {_BLD}Source IP: {_ip:<20}{_RST}  │  Events: {len(_evts)}  │  Peak Urgency: {_BLD}{_max_urg}/10{_RST}")
        print(f"    Incident types  : {_event_types}")

        if _chain:
            _path = " → ".join(_chain.get("stages_seen", []))
            print(f"    Kill chain path : {_CYN}{_path}{_RST}  →  {_RED}next: {_chain['next_stage']}{_RST}")
            print(f"    Confidence      : {_conf_badge(_chain['confidence'])}")
        else:
            _svms = list({e["asset_context"]["svm"] for e in _evts if e["asset_context"]["svm"] != "N/A"})
            if _svms:
                print(f"    Affected SVMs   : {', '.join(_svms)}")

        # Print highest-urgency event's top action
        _hi_evt = max(_evts, key=lambda e: e["urgency_score"])
        _top_rec = (_hi_evt.get("recommended_actions") or ["—"])[0]
        print(f"    Top action      : {_YEL}{_top_rec}{_RST}")

# SVM-level correlation (if any SVMs are known)
_svm_multi = {k: v for k, v in _by_svm.items() if len(v) > 1}
if _svm_multi:
    print(f"\n  {_BLD}SVM-level multi-event correlation:{_RST}")
    for _svm, _s_evts in sorted(_svm_multi.items(), key=lambda kv: -len(kv[1])):
        _types = ", ".join({e["event_type"] for e in _s_evts})
        print(f"    SVM: {_svm:<20}  {len(_s_evts)} events  [{_types}]")

print()

# ── SECTION 5: REMEDIATION ACTION SUMMARY ────────────────────────────────────
print(f"{_BLD}{'─'*_W}{_RST}")
print(f"  {_BLD}⑤ REMEDIATION ACTION SUMMARY  (consolidated ONTAP/DII API calls){_RST}")
print(f"{'─'*_W}")
print(f"\n  {_BLD}--- REACTIVE CONTAINMENT CALLS  (de-duplicated, sorted by urgency) ---{_RST}")
print(f"  {_DIM}{'#':<3}  {'ACTION':<38}  {'METHOD':<6}  {'ENDPOINT':<44}  FROM (urgency){_RST}")
print(f"  {'─'*3}  {'─'*38}  {'─'*6}  {'─'*44}  {'─'*14}")

for _ci, (_urg_s, _call, _eid) in enumerate(_deduped_calls[:18], 1):
    _action   = _call.get("action", "—")[:38]
    _method   = _call.get("method", "—")[:6]
    _endpoint = _call.get("endpoint", "—")[:44]
    _method_c = _RED if _method in ("DELETE", "PATCH") else (_YEL if _method == "POST" else _GRN)
    print(f"  {_ci:<3}  {_action:<38}  {_method_c}{_method:<6}{_RST}  {_DIM}{_endpoint:<44}{_RST}  urg={_urg_s}/10")

if len(_deduped_calls) > 18:
    print(f"  {_DIM}  … {len(_deduped_calls) - 18} more de-duplicated actions (omitted for brevity){_RST}")

print(f"\n  {_BLD}--- PROACTIVE PRE-EMPTIVE CALLS  (from threat hunter, most urgent first) ---{_RST}")
print(f"  {_DIM}{'#':<3}  {'METHOD':<6}  {'ENDPOINT':<50}  PURPOSE{_RST}")
print(f"  {'─'*3}  {'─'*6}  {'─'*50}  {'─'*30}")

for _pi, _pcall in enumerate(_proactive_calls[:8], 1):
    _pm  = _pcall.get("method", "—")[:6]
    _pe  = _pcall.get("endpoint", "—")[:50]
    _pp  = _pcall.get("purpose", "—")[:40]
    _pmc = _RED if _pm in ("DELETE", "PATCH") else (_YEL if _pm == "POST" else _GRN)
    print(f"  {_pi:<3}  {_pmc}{_pm:<6}{_RST}  {_DIM}{_pe:<50}{_RST}  {_pp}")

print()
_total_api = len(_deduped_calls) + len(_proactive_calls)
print(f"  {_BLD}Total API calls to execute: {_total_api}{_RST}  "
      f"({len(_deduped_calls)} reactive + {len(_proactive_calls)} proactive)")

# ── FOOTER ────────────────────────────────────────────────────────────────────
print(f"\n{'═'*_W}")
print(f"  {_BLD}🏁  END OF SOC REPORT{_RST}  │  Threat Posture: {_posture_label}  │  "
      f"Score: {_BLD}{_posture:.1f}/10{_RST}")
print(f"  {_DIM}⚠  All API endpoints are templates — substitute UUIDs / credentials before execution.{_RST}")
print(f"{'═'*_W}\n")

# ── STRUCTURED OUTPUTS ────────────────────────────────────────────────────────
soc_dashboard_posture_score   = _posture
soc_dashboard_ranked_alerts   = _ranked
soc_dashboard_watchlist       = _watchlist
soc_dashboard_campaigns       = _sorted_campaigns
soc_dashboard_remediation_api = _deduped_calls
