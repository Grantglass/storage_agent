
# relay_triage_report
# Connected ONLY to soc_analyst_agent (single 'output' source — no conflict).
# Reads hunter output from /tmp/soc_hunter_output.txt written by relay_hunter_output.
# Exposes 'triage_report' (analyst text) and 'hunter_output' (threat hunt text)
# for the soc_incident_dashboard.

import os

triage_report = output    # soc_analyst_agent's deep-triage text

# Read hunter output from shared file written by relay_hunter_output
with open("/tmp/soc_hunter_output.txt") as _f:
    hunter_output = _f.read()

print(f"✅ Triage report : {len(triage_report)} chars")
print(f"✅ Hunter output : {len(hunter_output)} chars (from file)")
