# Event schema (v0.1 - PROPOSAL, to be agreed by all three members)

One JSON object per event, stored as JSON Lines (`.jsonl`).

```json
{
  "event_id": "web-000123",
  "source": "web",
  "timestamp": "2026-03-04T10:21:07Z",
  "schema": {"client_ip": "203.0.113.5", "method": "GET", "status": 200},
  "untrusted": {"http_user_agent": "Mozilla/5.0 ...", "uri_query": "id=4"},
  "raw": "203.0.113.5 - - [04/Mar/2026:10:21:07 +0000] \"GET ...",
  "labels": {
    "injected": true,
    "payload_id": "override-017",
    "payload_category": "instruction_override",
    "target_field": "http_user_agent",
    "ground_truth_triage": "benign"
  }
}
```

## Rules
- `source` is one of: `ssh`, `web`, `windows_event`, `dns`.
- `schema` holds trusted fields, `untrusted` holds attacker-controlled fields
  (the split is defined in `attacks/taxonomy/fields.yaml`).
- `raw` is the original log line (or serialized event) so parsers can be tested from raw input.
- `labels.injected` = a payload is present. `labels.ground_truth_triage` =
  what the event really is: `benign`, `suspicious`, or `malicious`.
  These are independent: ISR uses the first, triage accuracy uses the second.
- For clean events, `payload_id`, `payload_category`, `target_field` are `null`.

## Interface 2 (Abeer): `ablate(event, strategy) -> safe_event`
`safe_event` keeps the same top-level keys except `untrusted`/`labels` handling
is decided by the strategy. Details to be agreed.
