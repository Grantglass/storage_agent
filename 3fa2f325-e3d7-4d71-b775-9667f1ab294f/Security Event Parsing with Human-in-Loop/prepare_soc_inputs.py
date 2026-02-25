# prepare_soc_inputs
# Pairs each enriched alert with its corresponding human decision,
# then exposes the highest-risk alert + decision for the SOC analyst GenAI agent.
# The top alert (by risk_score) is prioritised — it carries the most intelligence value.

# Build a lookup of human decisions by event_id for O(1) matching
_decision_map = {d["event_id"]: d for d in human_decision}

# Pair each enriched alert with its human decision
_soc_pairs = []
for _a in enriched_alert:
    _d = _decision_map.get(_a["event_id"])
    if _d:
        _soc_pairs.append({"alert": _a, "decision": _d})

# Sort by risk_score descending — highest risk gets the deep AI triage
_soc_pairs.sort(key=lambda p: p["alert"]["risk_score"], reverse=True)

print(f"🔗 Paired {len(_soc_pairs)} alerts with human decisions for SOC agent triage.\n")
print(f"{'#':<4} {'event_id':<38} {'severity':<10} {'verdict':<15} {'risk_score'}")
print("-" * 85)
for _i, _p in enumerate(_soc_pairs, 1):
    _al = _p["alert"]
    _de = _p["decision"]
    print(
        f"{_i:<4} {_al['event_id']:<38} {_al['severity']:<10} "
        f"{_de['verdict']:<15} {_al['risk_score']}"
    )

# Expose the highest-risk alert + its human decision to the GenAI SOC agent
alert   = _soc_pairs[0]["alert"]
decision = _soc_pairs[0]["decision"]

print(f"\n🎯 Top-risk alert selected for GenAI SOC triage:")
print(f"   event_id   : {alert['event_id']}")
print(f"   event_type : {alert['event_type']}")
print(f"   severity   : {alert['severity']}  |  risk_score: {alert['risk_score']}/15")
print(f"   source_ip  : {alert['source_ip']}")
print(f"   triage     : {alert['triage']}")
print(f"   verdict    : {decision['verdict']}  (reviewed_by: {decision['reviewed_by']})")
