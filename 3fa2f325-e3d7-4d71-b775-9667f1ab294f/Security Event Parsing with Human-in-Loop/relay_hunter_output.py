
# relay_hunter_output
# Bridges proactive_threat_hunter (Python Coding Agent) output to downstream consumers.
# Saves forward-looking threat intel to filesystem so the SOC dashboard can read it
# without creating variable name conflicts with the reactive pipeline.

import json

# Summarise top-level proactive_intel fields
_summary = proactive_intel.get("summary", {})

print("╔══════════════════════════════════════════════════════════════════════╗")
print("║   🔮  PROACTIVE THREAT HUNTER — Output Relay                        ║")
print("╚══════════════════════════════════════════════════════════════════════╝")
print(f"\n  Threat Vector   : {proactive_intel['predicted_threat_vector'][:70]}")
print(f"  Kill Chain Stage: {proactive_intel['kill_chain_stage']}")
print(f"  Confidence      : {proactive_intel['confidence_score']:.0%}")
print(f"  Time to Impact  : {proactive_intel['time_to_impact']}")
print(f"\n  Top Pre-emptive Action:")
print(f"    {proactive_intel['preemptive_actions'][0][:72]}")
print(f"\n  ONTAP API Calls : {len(proactive_intel['ontap_api_calls'])} queued on most-urgent alert")
print(f"  Total Alerts    : {_summary.get('total_alerts', '?')}")
print(f"  Reactive Gaps   : {_summary.get('missed_by_reactive', '?')} alerts missed by reactive pipeline")
print(f"  High Confidence : {_summary.get('high_confidence_count', '?')} threats at ≥75% confidence")

# Persist structured intel to shared filesystem for SOC dashboard
_payload = {
    "predicted_threat_vector": proactive_intel["predicted_threat_vector"],
    "kill_chain_stage":        proactive_intel["kill_chain_stage"],
    "confidence_score":        proactive_intel["confidence_score"],
    "time_to_impact":          proactive_intel["time_to_impact"],
    "preemptive_actions":      proactive_intel["preemptive_actions"],
    "ontap_api_calls_count":   len(proactive_intel["ontap_api_calls"]),
    "summary":                 _summary,
}

with open("/tmp/soc_hunter_output.txt", "w") as _f:
    # Write human-readable summary + JSON payload
    _f.write("=== PROACTIVE THREAT HUNTER INTELLIGENCE REPORT ===\n\n")
    _f.write(f"Threat Vector   : {proactive_intel['predicted_threat_vector']}\n")
    _f.write(f"Kill Chain Stage: {proactive_intel['kill_chain_stage']}\n")
    _f.write(f"Confidence      : {proactive_intel['confidence_score']:.0%}\n")
    _f.write(f"Time to Impact  : {proactive_intel['time_to_impact']}\n\n")
    _f.write("Pre-emptive Actions:\n")
    for _i, _act in enumerate(proactive_intel["preemptive_actions"], 1):
        _f.write(f"  {_i}. {_act}\n")
    _f.write(f"\nSummary: {json.dumps(_summary, indent=2)}\n")

print(f"\n✅  proactive_intel saved → /tmp/soc_hunter_output.txt")
print(f"✅  relay_hunter_output complete — proactive intel available for SOC dashboard")
