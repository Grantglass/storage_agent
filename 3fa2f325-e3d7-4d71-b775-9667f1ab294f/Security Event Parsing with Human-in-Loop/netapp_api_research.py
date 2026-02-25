
"""
NetApp ONTAP REST API & Data Infrastructure Insights (DII) REST API
Research Reference: Authentication, Key Event Fields, Webhook/Polling Mechanisms
Sources: NetApp ONTAP REST API documentation, DII REST API documentation
"""

# ─────────────────────────────────────────────────
# SECTION 1: NETAPP ONTAP REST API
# ─────────────────────────────────────────────────

ontap_base = {
    "base_url": "https://<cluster-mgmt-ip>/api",
    "version": "ONTAP 9.6+",
    "swagger_ui": "https://<cluster-mgmt-ip>/docs/api",
    "openapi_spec": "https://<cluster-mgmt-ip>/api?return_records=true",
}

# --- Authentication ---
ontap_auth = {
    "basic_auth": {
        "method": "HTTP Basic Authentication",
        "header": "Authorization: Basic <base64(user:password)>",
        "notes": "Supported for all API calls; fine for dev/test but not recommended for prod",
    },
    "certificate_auth": {
        "method": "Mutual TLS (mTLS) / Client Certificate",
        "header": "Uses client cert + private key",
        "notes": "Preferred for production; install client cert on ONTAP cluster",
        "endpoint": "POST /security/certificates",
    },
    "oauth2": {
        "method": "OAuth 2.0 Bearer Token (ONTAP 9.14+)",
        "header": "Authorization: Bearer <token>",
        "idp": "External identity provider (Entra ID, Okta, etc.)",
        "notes": "Recommended for modern deployments",
    },
    "api_key": {
        "notes": "No native API key; use a service account with Basic Auth or cert auth",
    },
}

# --- Security & Audit Log Endpoints ---
ontap_security_endpoints = [
    {
        "endpoint": "GET /security/audit/messages",
        "description": "Retrieve audit log messages (EMS-backed audit trail)",
        "key_params": {
            "time.gte": "ISO8601 start time filter",
            "time.lte": "ISO8601 end time filter",
            "index.gte": "Start from a specific log index (polling cursor)",
            "message_name": "Filter by event/message name",
            "severity": "emergency|alert|critical|error|notice|informational|debug",
            "fields": "Comma-separated list of fields to return",
            "max_records": "Page size (default 20, max 1000)",
            "return_timeout": "Long-poll wait (seconds)",
        },
    },
    {
        "endpoint": "GET /security/audit",
        "description": "Get cluster audit settings (which events are logged)",
        "key_fields": ["enabled", "log_path", "log_size", "log_count"],
    },
    {
        "endpoint": "GET /security/audit/destinations",
        "description": "List remote syslog/audit forwarding destinations",
    },
    {
        "endpoint": "POST /security/audit/destinations",
        "description": "Add a remote syslog destination (forward audit events)",
    },
    {
        "endpoint": "GET /security/roles",
        "description": "List RBAC roles",
    },
    {
        "endpoint": "GET /security/accounts",
        "description": "List user accounts and their auth methods",
    },
    {
        "endpoint": "GET /security/login/messages",
        "description": "Login banner and MOTD configuration",
    },
    {
        "endpoint": "GET /support/ems/events",
        "description": "EMS (Event Management System) events — primary source of storage events",
        "key_params": {
            "time.gte": "Start time filter",
            "message.name": "EMS message name filter",
            "message.severity": "Severity filter",
            "index.gte": "Polling cursor (event index)",
            "max_records": "Page size",
            "return_timeout": "Long-poll timeout",
        },
    },
    {
        "endpoint": "GET /support/ems/messages",
        "description": "Catalog of all defined EMS message types",
    },
    {
        "endpoint": "GET /support/ems/destinations",
        "description": "List EMS notification destinations (email, syslog, REST webhook)",
    },
    {
        "endpoint": "POST /support/ems/destinations",
        "description": "Register an EMS webhook/REST destination for real-time push events",
        "body_example": {
            "name": "soc-webhook",
            "type": "rest_api",
            "destination": "https://your-soc-endpoint/api/ems",
            "filters": [{"name": "security-events-filter"}],
        },
    },
    {
        "endpoint": "POST /support/ems/filters",
        "description": "Create EMS filter (define which events to route to a destination)",
        "body_example": {
            "name": "security-events-filter",
            "rules": [
                {"type": "include", "message_criteria": {"severities": "emergency,alert,error", "name_pattern": "sec.*"}},
                {"type": "include", "message_criteria": {"name_pattern": "audit.*"}},
            ],
        },
    },
]

# --- Key Audit/Security Event Fields ---
ontap_event_schema = {
    "source": "/security/audit/messages and /support/ems/events",
    "fields": {
        "index": "Monotonically increasing event ID (use as polling cursor)",
        "time": "ISO8601 timestamp of the event",
        "message_name": "EMS message name (e.g., 'security.login.fail', 'audit.log.create')",
        "severity": "emergency | alert | critical | error | notice | informational | debug",
        "node.name": "Cluster node name",
        "node.uuid": "Node UUID",
        "svm.name": "Storage VM name",
        "svm.uuid": "SVM UUID",
        "parameters": "List of key-value pairs with event-specific details",
        "log_message": "Human-readable event description",
        "source": "Component that generated the event",
    },
    "important_security_message_names": [
        "security.login.fail",
        "security.login.success",
        "security.password.change",
        "security.account.lock",
        "security.certificate.expire",
        "audit.log.create",
        "audit.log.rotate",
        "vscan.virus.found",
        "fpolicy.event.blocked",
        "net.firewall.policy.violation",
        "mgmt.api.access",
        "mgmt.audit.log.full",
    ],
}

# --- Polling vs Webhook Mechanisms ---
ontap_event_delivery = {
    "polling": {
        "mechanism": "GET /support/ems/events with index.gte cursor",
        "how_it_works": (
            "Store the last seen 'index' value. On next poll, use "
            "?index.gte=<last_index+1> to retrieve only new events. "
            "Use max_records for pagination."
        ),
        "long_poll": "Add return_timeout=<seconds> (e.g., 30) for server-side hold until events arrive",
        "recommended_interval": "30-60s for near-real-time; use return_timeout for efficiency",
    },
    "webhook_push": {
        "mechanism": "POST /support/ems/destinations (type: rest_api)",
        "how_it_works": (
            "ONTAP POSTs JSON event payload to your endpoint on each matching event. "
            "No polling needed. Requires ONTAP 9.6+ and network reachability from cluster."
        ),
        "payload_format": "JSON — same schema as EMS event object",
        "auth_on_webhook": "Supports optional client certificate or basic auth on webhook endpoint",
    },
    "syslog_forward": {
        "mechanism": "POST /security/audit/destinations",
        "how_it_works": "Forward audit logs to syslog/SIEM (UDP/TCP, TLS optional)",
    },
}

# ─────────────────────────────────────────────────
# SECTION 2: DATA INFRASTRUCTURE INSIGHTS (DII) REST API
# ─────────────────────────────────────────────────

dii_base = {
    "product": "NetApp Data Infrastructure Insights (formerly Cloud Insights)",
    "base_url": "https://<tenant-id>.c01.cloudinsights.netapp.com/rest/v1",
    "docs": "https://docs.netapp.com/us-en/data-infrastructure-insights/API_Overview.html",
    "api_explorer": "https://<tenant-id>.c01.cloudinsights.netapp.com/rest/v1/",
    "swagger": "https://<tenant-id>.c01.cloudinsights.netapp.com/swagger-ui/",
}

# --- Authentication ---
dii_auth = {
    "method": "API Access Token (Bearer Token)",
    "header": "X-CloudInsights-ApiKey: <your-api-token>",
    "alt_header": "Authorization: Bearer <your-api-token>",
    "how_to_generate": (
        "In DII UI: Admin -> API Access -> + API Access Token. "
        "Choose token type: Read Only, Write, or Admin."
    ),
    "token_types": {
        "Read Only": "Query assets, metrics, alerts (use for SOC integrations)",
        "Write": "Create annotations, modify assets",
        "Admin": "Full control including user management",
    },
    "expiration": "Configurable (7 days to never); rotate regularly in production",
    "tls": "All API calls must use HTTPS",
}

# --- Anomaly & Performance Alert Endpoints ---
dii_alert_endpoints = [
    {
        "endpoint": "GET /rest/v1/alerts",
        "description": "List active and historical performance/anomaly alerts",
        "key_params": {
            "timeRange": "Time window, e.g., '3h', '24h', '7d'",
            "status": "active | resolved | acknowledged",
            "severity": "critical | warning | info",
            "type": "performance | capacity | anomaly",
            "limit": "Max results per page (default 100)",
            "offset": "Pagination offset",
            "startTime": "Epoch milliseconds",
            "endTime": "Epoch milliseconds",
        },
    },
    {
        "endpoint": "GET /rest/v1/alerts/{id}",
        "description": "Get detailed information about a specific alert",
    },
    {
        "endpoint": "GET /rest/v1/alerts/count",
        "description": "Get total count of alerts matching filters (useful for health checks)",
    },
    {
        "endpoint": "GET /rest/v1/anomalies",
        "description": "Retrieve AI/ML-detected storage anomalies",
        "notes": "Requires Workload Security or AI-driven anomaly detection license",
        "key_params": {
            "objectType": "volume | disk | node | datastore",
            "timeRange": "e.g., '1h', '24h'",
            "severity": "critical | warning",
        },
    },
    {
        "endpoint": "GET /rest/v1/assets/storages",
        "description": "List storage arrays monitored by DII",
    },
    {
        "endpoint": "GET /rest/v1/assets/volumes",
        "description": "List volumes with performance metrics",
        "key_params": {
            "fields": "Comma-separated metric fields (iops, latency, throughput)",
            "objectType": "volume",
        },
    },
    {
        "endpoint": "GET /rest/v1/metrics",
        "description": "Query raw performance metrics (time-series)",
        "key_params": {
            "objectType": "volume | node | disk | qtree",
            "metric": "iops.read | latency.write | throughput.total | cpu.busy",
            "startTime": "Epoch ms",
            "endTime": "Epoch ms",
            "resolution": "5m | 1h | 1d",
        },
    },
    {
        "endpoint": "POST /rest/v1/queries",
        "description": "Advanced query builder — filter any asset type with complex criteria",
        "body_example": {
            "objectType": "Alert",
            "filters": [
                {"name": "severity", "operator": "=", "value": "critical"},
                {"name": "status", "operator": "=", "value": "active"},
            ],
            "fields": ["id", "name", "severity", "status", "raisedTime", "objectType", "affectedObjects"],
        },
    },
    {
        "endpoint": "GET /rest/v1/workloadSecurity/alerts",
        "description": "Workload Security alerts — insider threat, ransomware detection",
        "key_params": {
            "startTime": "Epoch ms",
            "endTime": "Epoch ms",
            "status": "open | resolved",
            "type": "ransomware | insider_threat | abnormal_user_behavior",
        },
    },
    {
        "endpoint": "GET /rest/v1/workloadSecurity/activities",
        "description": "Individual file access activities flagged as anomalous",
        "key_params": {
            "alertId": "Filter by parent alert",
            "startTime": "Epoch ms",
            "endTime": "Epoch ms",
            "user": "Username filter",
        },
    },
    {
        "endpoint": "GET /rest/v1/workloadSecurity/users",
        "description": "Users monitored by Workload Security",
    },
]

# --- Key Alert/Anomaly Event Fields ---
dii_event_schema = {
    "alert_object": {
        "id": "Unique alert ID (string UUID)",
        "name": "Alert policy name that triggered",
        "description": "Human-readable description of the alert condition",
        "severity": "critical | warning | info",
        "status": "active | resolved | acknowledged",
        "type": "performance | capacity | anomaly | workload_security",
        "raisedTime": "Epoch milliseconds when alert was first raised",
        "clearedTime": "Epoch ms when alert resolved (null if still active)",
        "affectedObjects": "[{type, id, name}] — assets impacted",
        "triggeredConditions": "[{metric, operator, threshold, observedValue}]",
        "relatedPolicies": "Policy name and ID that matched",
        "annotations": "Custom tags/annotations on the affected asset",
    },
    "workload_security_alert": {
        "id": "Alert UUID",
        "type": "ransomware | insider_threat | abnormal_user_behavior",
        "severity": "critical | warning",
        "status": "open | resolved",
        "user": "Username of the actor",
        "client_ip": "Source IP of file access",
        "svm": "Storage VM name",
        "volume": "Volume name",
        "alertTime": "Epoch ms",
        "activityCount": "Number of anomalous file operations",
        "fileExtensionsImpacted": "List of file extensions (e.g., .vmdk, .docx)",
        "encryptedFiles": "Count of files potentially encrypted (ransomware indicator)",
        "policyName": "Workload Security policy that triggered",
    },
}

# --- Webhook / Notification Mechanisms ---
dii_event_delivery = {
    "webhook": {
        "mechanism": "DII UI: Admin -> Notifications -> Webhooks",
        "how_it_works": (
            "Configure DII to POST JSON payloads to your SOC/SIEM endpoint "
            "when alert conditions are met. No API polling needed for real-time."
        ),
        "triggers": "Alert raised | Alert cleared | Alert severity changed | Workload Security alert",
        "auth_options": "Custom HTTP headers (add Authorization header to webhook config)",
        "api_config_endpoint": "POST /rest/v1/admin/notifications (programmatic webhook setup)",
        "supported_targets": "Generic webhook, Slack, PagerDuty, ServiceNow, Teams, Email",
    },
    "polling": {
        "mechanism": "GET /rest/v1/alerts with startTime/endTime params",
        "how_it_works": "Track latest raisedTime or id seen; poll on schedule (60-300s recommended)",
    },
    "email_smtp": {
        "mechanism": "Built-in email notifications — configure in DII UI",
        "how_it_works": "Less useful for SIEM/SOC programmatic ingestion; better for human alerting",
    },
}

# ─────────────────────────────────────────────────
# SECTION 3: INTEGRATION SUMMARY & RECOMMENDATIONS
# ─────────────────────────────────────────────────

integration_summary = {
    "recommended_architecture": {
        "realtime_events": {
            "ONTAP_audit": "Configure EMS webhook: POST /support/ems/destinations (type: rest_api)",
            "DII_alerts": "Configure DII webhook: Admin -> Notifications -> Webhooks",
            "result": "SOC endpoint receives push events within seconds of occurrence",
        },
        "batch_polling_fallback": {
            "ONTAP": "GET /support/ems/events?index.gte=<cursor>&return_timeout=30",
            "DII": "GET /rest/v1/alerts?startTime=<last_poll_epoch>&status=active",
        },
    },
    "auth_summary": {
        "ONTAP": "Basic Auth (dev) -> Certificate Auth (prod) -> OAuth2 (ONTAP 9.14+)",
        "DII": "API Access Token in X-CloudInsights-ApiKey header",
    },
    "critical_event_types_for_soc": [
        "ONTAP: security.login.fail — brute force detection",
        "ONTAP: audit.log.* — audit trail tampering detection",
        "ONTAP: fpolicy.event.blocked — file access control violations",
        "ONTAP: vscan.virus.found — malware on NAS shares",
        "ONTAP: mgmt.api.access — unauthorized API usage",
        "DII Workload Security: ransomware — mass encryption events",
        "DII Workload Security: insider_threat — abnormal user data access",
        "DII Workload Security: abnormal_user_behavior — privilege escalation patterns",
        "DII Performance: iops.total spike — potential exfiltration or cryptomining I/O",
        "DII Capacity: volume.nearly.full — potential log flooding/deletion attack",
    ],
}

# ─────────────────────────────────────────────────
# PRINT REPORT
# ─────────────────────────────────────────────────

SEP = "=" * 70
sep = "-" * 70

print(SEP)
print("  NetApp ONTAP REST API — Security & Audit Log Events")
print(SEP)

print("\nBASE URL:", ontap_base["base_url"])
print("Swagger UI:", ontap_base["swagger_ui"])
print("Version:", ontap_base["version"])

print(f"\n{sep}")
print("AUTHENTICATION OPTIONS")
print(sep)
for _auth_method, _detail in ontap_auth.items():
    if "method" in _detail:
        print(f"  [{_auth_method.upper()}] {_detail['method']}")
        if "header" in _detail:
            print(f"    Header: {_detail['header']}")
        print(f"    Notes:  {_detail.get('notes', '')}")

print(f"\n{sep}")
print("SECURITY & AUDIT ENDPOINTS")
print(sep)
for _ep in ontap_security_endpoints:
    print(f"\n  {_ep['endpoint']}")
    print(f"    -> {_ep['description']}")
    for _pk, _pv in _ep.get("key_params", {}).items():
        print(f"      * {_pk}: {_pv}")

print(f"\n{sep}")
print("KEY EVENT FIELDS (EMS / Audit Log)")
print(sep)
for _field, _desc in ontap_event_schema["fields"].items():
    print(f"  * {_field}: {_desc}")
print("\n  Important security message names:")
for _msg_name in ontap_event_schema["important_security_message_names"]:
    print(f"    - {_msg_name}")

print(f"\n{sep}")
print("EVENT DELIVERY: POLLING vs WEBHOOK")
print(sep)
for _mode, _delivery in ontap_event_delivery.items():
    print(f"\n  [{_mode.upper()}] {_delivery['mechanism']}")
    print(f"    {_delivery['how_it_works']}")

print()
print(SEP)
print("  NetApp Data Infrastructure Insights (DII) REST API")
print("  Storage Anomaly & Performance Alert Data")
print(SEP)

print("\nBASE URL:", dii_base["base_url"])
print("Docs:    ", dii_base["docs"])
print("Swagger: ", dii_base["swagger"])

print(f"\n{sep}")
print("AUTHENTICATION")
print(sep)
print(f"  Method: {dii_auth['method']}")
print(f"  Header: {dii_auth['header']}")
print(f"  Alt Header: {dii_auth['alt_header']}")
print(f"  How to get token: {dii_auth['how_to_generate']}")
print("  Token types:")
for _ttype, _tdesc in dii_auth["token_types"].items():
    print(f"    * {_ttype}: {_tdesc}")

print(f"\n{sep}")
print("ANOMALY & PERFORMANCE ALERT ENDPOINTS")
print(sep)
for _ep in dii_alert_endpoints:
    print(f"\n  {_ep['endpoint']}")
    print(f"    -> {_ep['description']}")
    for _pk, _pv in _ep.get("key_params", {}).items():
        print(f"      * {_pk}: {_pv}")
    if "notes" in _ep:
        print(f"    NOTE: {_ep['notes']}")

print(f"\n{sep}")
print("KEY ALERT FIELDS")
print(sep)
print("  [Standard Alert Object]")
for _field, _val in dii_event_schema["alert_object"].items():
    print(f"  * {_field}: {_val}")
print("\n  [Workload Security Alert — Ransomware/Insider Threat]")
for _field, _val in dii_event_schema["workload_security_alert"].items():
    print(f"  * {_field}: {_val}")

print(f"\n{sep}")
print("EVENT DELIVERY: WEBHOOK & POLLING")
print(sep)
for _mode, _delivery in dii_event_delivery.items():
    print(f"\n  [{_mode.upper()}] {_delivery['mechanism']}")
    print(f"    {_delivery['how_it_works']}")

print()
print(SEP)
print("  INTEGRATION SUMMARY & SOC RECOMMENDATIONS")
print(SEP)
print("\n  Recommended Real-Time Architecture:")
for _k, _v in integration_summary["recommended_architecture"]["realtime_events"].items():
    print(f"    * {_k}: {_v}")
print("\n  Batch Polling Fallback:")
for _k, _v in integration_summary["recommended_architecture"]["batch_polling_fallback"].items():
    print(f"    * {_k}: {_v}")
print("\n  Auth Summary:")
for _k, _v in integration_summary["auth_summary"].items():
    print(f"    * {_k}: {_v}")
print("\n  Critical Event Types for SOC:")
for _evt in integration_summary["critical_event_types_for_soc"]:
    print(f"    - {_evt}")

print(f"\n{sep}")
print("  Research complete. Reference structures above for SOC integration.")
print(sep)
