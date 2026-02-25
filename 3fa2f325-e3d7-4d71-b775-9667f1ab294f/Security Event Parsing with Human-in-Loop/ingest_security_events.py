
"""
ingest_security_events
======================
Fetches storage security events from:
  1. NetApp ONTAP EMS REST API  — Basic Auth
  2. NetApp Data Infrastructure Insights (DII) REST API  — API token (Bearer)

Falls back to realistic simulated storage events when credentials are absent.
All events are normalised into a unified schema then fanned out with spread().
Variable per slice: storage_alert (dict)
"""

import uuid
import base64
import json
import random
from datetime import datetime, timedelta, timezone

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — fill in your real credentials / endpoints to enable live mode.
# Leave as placeholders to run in simulation mode.
# ─────────────────────────────────────────────────────────────────────────────

ONTAP_HOST     = ""          # e.g. "192.168.10.50"  (cluster mgmt IP/hostname)
ONTAP_USER     = ""          # e.g. "admin"
ONTAP_PASSWORD = ""          # e.g. "NetApp123!"
ONTAP_VERIFY_SSL = False     # Set True in production with valid cert

DII_TENANT_URL = ""          # e.g. "https://abc123.c01.cloudinsights.netapp.com"
DII_API_TOKEN  = ""          # Read-only API Access Token from DII UI

# How many hours back to look for events (polling window)
POLL_HOURS = 1

# Max events to ingest per source
MAX_ONTAP_EVENTS = 10
MAX_DII_EVENTS   = 10

# ─────────────────────────────────────────────────────────────────────────────
# UNIFIED EVENT SCHEMA
# ─────────────────────────────────────────────────────────────────────────────

def normalize_ontap_ems(raw: dict) -> dict:
    """Normalize a raw ONTAP EMS event into the unified storage-alert schema."""
    _msg    = raw.get("message", {})
    _node   = raw.get("node", {})
    _svm    = raw.get("svm", {})
    _params = {p["name"]: p["value"] for p in raw.get("parameters", [])} if raw.get("parameters") else {}

    # Map ONTAP severity -> unified severity
    _sev_map = {
        "emergency": "CRITICAL",
        "alert":     "CRITICAL",
        "critical":  "CRITICAL",
        "error":     "HIGH",
        "notice":    "MEDIUM",
        "informational": "LOW",
        "debug":     "LOW",
    }
    _raw_sev = _msg.get("severity", "informational")
    _severity = _sev_map.get(_raw_sev.lower(), "MEDIUM")

    # Map EMS message name -> event type
    _msg_name = _msg.get("name", "unknown")
    _type_map = {
        "security.login.fail":         "BRUTE_FORCE",
        "security.account.lock":       "BRUTE_FORCE",
        "security.password.change":    "PRIVILEGE_ESCALATION",
        "fpolicy.event.blocked":       "UNAUTHORIZED_ACCESS",
        "vscan.virus.found":           "MALWARE_DETECTED",
        "mgmt.api.access":             "UNAUTHORIZED_ACCESS",
        "audit.log.create":            "AUDIT_EVENT",
        "audit.log.rotate":            "AUDIT_EVENT",
        "mgmt.audit.log.full":         "AUDIT_EVENT",
        "net.firewall.policy.violation": "POLICY_VIOLATION",
        "security.certificate.expire": "CERTIFICATE_ALERT",
    }
    _event_type = _type_map.get(_msg_name)
    if not _event_type:
        if "login" in _msg_name or "auth" in _msg_name:
            _event_type = "BRUTE_FORCE"
        elif "audit" in _msg_name:
            _event_type = "AUDIT_EVENT"
        elif "security" in _msg_name or "policy" in _msg_name:
            _event_type = "POLICY_VIOLATION"
        else:
            _event_type = "STORAGE_EVENT"

    _source_ip = _params.get("client_ip", _params.get("src_ip", _params.get("address", "0.0.0.0")))

    return {
        "event_id":    raw.get("index", str(uuid.uuid4())),
        "source":      "ONTAP_EMS",
        "timestamp":   raw.get("time", datetime.now(timezone.utc).isoformat()),
        "severity":    _severity,
        "event_type":  _event_type,
        "source_ip":   _source_ip,
        "description": raw.get("log_message", _msg_name),
        "raw_log":     json.dumps({
            "index":    raw.get("index"),
            "msg_name": _msg_name,
            "node":     _node.get("name"),
            "svm":      _svm.get("name"),
            "severity": _raw_sev,
            "params":   _params,
        }),
        "node":        _node.get("name", ""),
        "svm":         _svm.get("name", ""),
        "msg_name":    _msg_name,
    }


def normalize_dii_alert(raw: dict) -> dict:
    """Normalize a raw DII alert into the unified storage-alert schema."""
    _sev_map = {
        "critical": "CRITICAL",
        "warning":  "HIGH",
        "info":     "LOW",
    }
    _type_map = {
        "ransomware":            "MALWARE_DETECTED",
        "insider_threat":        "DATA_EXFILTRATION",
        "abnormal_user_behavior":"PRIVILEGE_ESCALATION",
        "performance":           "ANOMALOUS_IO",
        "capacity":              "CAPACITY_ALERT",
        "anomaly":               "ANOMALOUS_IO",
        "workload_security":     "UNAUTHORIZED_ACCESS",
    }

    _alert_type = raw.get("type", "anomaly").lower()
    _event_type = _type_map.get(_alert_type, "STORAGE_EVENT")
    _severity   = _sev_map.get(raw.get("severity", "info").lower(), "MEDIUM")

    # raisedTime is epoch ms
    _raised_ms  = raw.get("raisedTime", raw.get("alertTime", 0))
    if _raised_ms:
        _ts = datetime.fromtimestamp(_raised_ms / 1000, tz=timezone.utc).isoformat()
    else:
        _ts = datetime.now(timezone.utc).isoformat()

    _affected   = raw.get("affectedObjects", [])
    _affected_str = ", ".join(
        f"{o.get('type','')}/{o.get('name','')}" for o in _affected
    ) if _affected else ""

    return {
        "event_id":    str(raw.get("id", uuid.uuid4())),
        "source":      "DII",
        "timestamp":   _ts,
        "severity":    _severity,
        "event_type":  _event_type,
        "source_ip":   raw.get("client_ip", raw.get("user", "N/A")),
        "description": raw.get("description", raw.get("name", "DII alert")),
        "raw_log":     json.dumps({
            "id":           raw.get("id"),
            "name":         raw.get("name"),
            "type":         _alert_type,
            "status":       raw.get("status"),
            "raisedTime":   _raised_ms,
            "affected":     _affected_str,
        }),
        "node":        "",
        "svm":         raw.get("svm", ""),
        "msg_name":    f"dii.{_alert_type}",
    }


# ─────────────────────────────────────────────────────────────────────────────
# LIVE FETCH: ONTAP EMS
# ─────────────────────────────────────────────────────────────────────────────

def fetch_ontap_ems_events() -> list:
    """Poll ONTAP EMS REST API for recent security events. Returns normalised list."""
    import urllib.request
    import urllib.error
    import ssl

    _base = f"https://{ONTAP_HOST}/api"
    _creds = base64.b64encode(f"{ONTAP_USER}:{ONTAP_PASSWORD}".encode()).decode()
    _headers = {
        "Authorization": f"Basic {_creds}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }

    _since = (datetime.now(timezone.utc) - timedelta(hours=POLL_HOURS)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    _params = (
        f"time.gte={_since}"
        f"&message.severity=emergency,alert,critical,error"
        f"&max_records={MAX_ONTAP_EVENTS}"
        f"&fields=index,time,message.name,message.severity,node.name,"
        f"node.uuid,svm.name,log_message,parameters"
    )

    _url = f"{_base}/support/ems/events?{_params}"

    _ctx = ssl.create_default_context()
    if not ONTAP_VERIFY_SSL:
        _ctx.check_hostname = False
        _ctx.verify_mode = ssl.CERT_NONE

    _req = urllib.request.Request(_url, headers=_headers)
    with urllib.request.urlopen(_req, context=_ctx, timeout=15) as _resp:
        _data = json.loads(_resp.read().decode())

    _raw_events = _data.get("records", [])
    return [normalize_ontap_ems(e) for e in _raw_events]


# ─────────────────────────────────────────────────────────────────────────────
# LIVE FETCH: DII
# ─────────────────────────────────────────────────────────────────────────────

def fetch_dii_alerts() -> list:
    """Poll DII REST API for recent alerts. Returns normalised list."""
    import urllib.request
    import ssl

    _base = f"{DII_TENANT_URL.rstrip('/')}/rest/v1"
    _headers = {
        "X-CloudInsights-ApiKey": DII_API_TOKEN,
        "Accept": "application/json",
    }

    _start_ms = int(
        (datetime.now(timezone.utc) - timedelta(hours=POLL_HOURS)).timestamp() * 1000
    )

    # Fetch both standard alerts and Workload Security alerts
    _events: list = []

    for _endpoint in [
        f"{_base}/alerts?startTime={_start_ms}&limit={MAX_DII_EVENTS}&status=active",
        f"{_base}/workloadSecurity/alerts?startTime={_start_ms}&status=open",
    ]:
        _req = urllib.request.Request(_endpoint, headers=_headers)
        _ctx = ssl.create_default_context()  # DII always uses valid certs
        with urllib.request.urlopen(_req, context=_ctx, timeout=15) as _resp:
            _data = json.loads(_resp.read().decode())
        # DII may return a list or {"results": [...]} wrapper
        _raw = _data if isinstance(_data, list) else _data.get("results", _data.get("alerts", []))
        _events.extend([normalize_dii_alert(e) for e in _raw[:MAX_DII_EVENTS]])

    return _events


# ─────────────────────────────────────────────────────────────────────────────
# SIMULATION FALLBACK: Realistic storage security events
# ─────────────────────────────────────────────────────────────────────────────

_ONTAP_EMS_MESSAGES = [
    ("security.login.fail",          "CRITICAL", "Multiple failed SSH login attempts from external host",  "10.10.5.211"),
    ("fpolicy.event.blocked",        "HIGH",     "FPolicy blocked file access: .vmdk read attempt by unauthorized process", "172.16.3.44"),
    ("vscan.virus.found",            "CRITICAL", "Vscan: Virus signature matched in CIFS share \\\\vol1\\share", "192.168.1.155"),
    ("security.account.lock",        "HIGH",     "Account 'svc-backup' locked after 5 failed authentications", "10.0.8.99"),
    ("mgmt.api.access",              "MEDIUM",   "REST API access to /api/security/accounts from untrusted IP", "203.0.113.42"),
    ("audit.log.create",             "LOW",      "Audit log segment created: /mroot/etc/log/mlog/audit.log.2", ""),
    ("net.firewall.policy.violation","HIGH",     "Firewall policy violation: TCP SYN flood on port 443", "45.33.32.156"),
    ("security.certificate.expire",  "MEDIUM",   "SSL certificate for SVM 'svm-prod' expires in 7 days", ""),
]

_DII_SIMULATED = [
    {"id": str(uuid.uuid4()), "type": "ransomware",            "severity": "critical", "status": "active",
     "name": "Ransomware Activity Detected", "raisedTime": int((datetime.now(timezone.utc)-timedelta(minutes=12)).timestamp()*1000),
     "description": "Mass file encryption detected on volume /vol/prod_data — 3,412 files in 4 minutes",
     "affectedObjects": [{"type":"volume","name":"/vol/prod_data"},{"type":"svm","name":"svm-prod"}],
     "client_ip": "192.168.10.77"},
    {"id": str(uuid.uuid4()), "type": "insider_threat",        "severity": "critical", "status": "active",
     "name": "Insider Threat: Large Data Exfiltration",        "raisedTime": int((datetime.now(timezone.utc)-timedelta(minutes=28)).timestamp()*1000),
     "description": "User 'jsmith' downloaded 42 GB in 10 minutes from NAS volume",
     "affectedObjects": [{"type":"volume","name":"/vol/finance"}],
     "client_ip": "10.5.2.18"},
    {"id": str(uuid.uuid4()), "type": "abnormal_user_behavior","severity": "warning",  "status": "active",
     "name": "Abnormal User Behaviour: Privilege Escalation Pattern",
     "raisedTime": int((datetime.now(timezone.utc)-timedelta(minutes=45)).timestamp()*1000),
     "description": "Service account 'svc-etl' accessing volumes outside normal scope (15 new volumes in 2 min)",
     "affectedObjects": [{"type":"svm","name":"svm-dev"}],
     "client_ip": "172.16.4.200"},
]

def generate_simulated_events() -> list:
    """Generate realistic simulated storage security events as fallback."""
    _events = []

    # ONTAP EMS simulated events
    for _msg_name, _sev, _desc, _ip in _ONTAP_EMS_MESSAGES:
        _sev_map = {"CRITICAL":"critical","HIGH":"error","MEDIUM":"notice","LOW":"informational"}
        _ts = datetime.now(timezone.utc) - timedelta(seconds=random.randint(30, POLL_HOURS * 3600))
        _raw = {
            "index":       random.randint(100000, 999999),
            "time":        _ts.isoformat(),
            "log_message": _desc,
            "message":     {"name": _msg_name, "severity": _sev_map.get(_sev, "notice")},
            "node":        {"name": random.choice(["node1","node2","node3"]), "uuid": str(uuid.uuid4())},
            "svm":         {"name": random.choice(["svm-prod","svm-dev","svm-dr"])},
            "parameters":  [{"name": "client_ip", "value": _ip}] if _ip else [],
        }
        _events.append(normalize_ontap_ems(_raw))

    # DII simulated events
    for _raw_dii in _DII_SIMULATED:
        _events.append(normalize_dii_alert(_raw_dii))

    return _events


# ─────────────────────────────────────────────────────────────────────────────
# MAIN INGESTION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

_ingested_events: list = []
_ontap_count   = 0
_dii_count     = 0
_mode          = "SIMULATION"

# Determine which sources are configured
_ontap_configured = bool(ONTAP_HOST and ONTAP_USER and ONTAP_PASSWORD)
_dii_configured   = bool(DII_TENANT_URL and DII_API_TOKEN)

if _ontap_configured:
    print(f"🔌 ONTAP credentials configured — attempting live fetch from {ONTAP_HOST} …")
    _ontap_events = fetch_ontap_ems_events()
    _ingested_events.extend(_ontap_events)
    _ontap_count = len(_ontap_events)
    print(f"   ✅ ONTAP EMS: {_ontap_count} events fetched")
    _mode = "LIVE"
else:
    print("⚠️  ONTAP credentials not configured — ONTAP EMS fetch skipped.")

if _dii_configured:
    print(f"🔌 DII credentials configured — attempting live fetch from {DII_TENANT_URL} …")
    _dii_events = fetch_dii_alerts()
    _ingested_events.extend(_dii_events)
    _dii_count = len(_dii_events)
    print(f"   ✅ DII: {_dii_count} alerts fetched")
    _mode = "LIVE"
else:
    print("⚠️  DII credentials not configured — DII alert fetch skipped.")

if not _ingested_events:
    print("\n📋 No live events — switching to SIMULATION fallback with realistic storage events.")
    _ingested_events = generate_simulated_events()
    _mode = "SIMULATION"

# Sort by timestamp descending (newest first)
_ingested_events.sort(key=lambda e: e["timestamp"], reverse=True)

# Deduplicate by event_id
_seen_ids: set = set()
_deduped: list = []
for _evt in _ingested_events:
    if _evt["event_id"] not in _seen_ids:
        _seen_ids.add(_evt["event_id"])
        _deduped.append(_evt)

security_events = _deduped

# ─────────────────────────────────────────────────────────────────────────────
# PRINT INGESTION SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

_SEP = "─" * 100
print(f"\n{'═'*100}")
print(f"  STORAGE SECURITY EVENT INGESTION  │  Mode: {_mode}  │  Events: {len(security_events)}")
print(f"  Sources: ONTAP EMS ({_ontap_count} live) + DII ({_dii_count} live)"
      + (f" + {len(security_events)} simulated" if _mode == 'SIMULATION' else ""))
print(f"{'═'*100}")
print(f"\n{'#':<4} {'Source':<12} {'Severity':<10} {'Event Type':<26} {'Source IP':<18} {'Description'}")
print(_SEP)
for _i, _ev in enumerate(security_events, 1):
    _desc_short = _ev["description"][:45] + "…" if len(_ev["description"]) > 45 else _ev["description"]
    print(
        f"{_i:<4} {_ev['source']:<12} {_ev['severity']:<10} "
        f"{_ev['event_type']:<26} {_ev['source_ip']:<18} {_desc_short}"
    )

print(f"\n{'─'*100}")
print(f"  Unified schema fields: event_id, source, timestamp, severity, event_type,")
print(f"  source_ip, description, raw_log, node, svm, msg_name")
print(f"{'─'*100}\n")

# ─────────────────────────────────────────────────────────────────────────────
# FAN OUT — each storage alert becomes an independent parallel slice
# storage_alert is the variable name consumed by downstream agent blocks.
# ─────────────────────────────────────────────────────────────────────────────
storage_alert = spread(security_events)

print(f"🚀 spread() called — {len(security_events)} storage alerts fanned out as independent parallel slices.")
print(f"   Downstream blocks receive: storage_alert (dict, unified schema)")
