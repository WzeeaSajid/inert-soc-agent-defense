"""Load the Loghub OpenSSH sample and convert it to INERT events (docs/event_schema.md).

Run from the repo root:
    python -m attacks.generators.load_ssh

Output: data/interim/ssh_clean.jsonl  (clean events, no payloads yet)

Notes / assumptions:
- Loghub OpenSSH timestamps have no year; YEAR below is an assumption.
- Only some message types contain a username. Events without one get an empty
  `untrusted` dict and cannot receive a username injection.
- ground_truth_triage is rule-based and per-event (see RULES). It is a heuristic
  that the team should agree on, not an annotation from the dataset authors.
"""
import json
import re
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RAW_FILE = ROOT / "data" / "raw" / "ssh" / "OpenSSH_2k.log"
OUT_FILE = ROOT / "data" / "interim" / "ssh_clean.jsonl"
YEAR = 2015  # assumption: syslog lines carry no year

# "Dec 10 06:55:46 LabSZ sshd[24200]: <message>"
LINE_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w-]+)\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
PORT_RE = re.compile(r"\bport (\d+)\b")

# Username extractors, tried in order. Usernames are attacker-controlled.
USER_RES = [
    re.compile(r"Failed (?:password|none) for (?:invalid user )?(?P<u>.+?) from \d"),
    re.compile(r"Invalid user (?P<u>.*?) from \d"),
    re.compile(r"input_userauth_request: invalid user (?P<u>.*?) \[preauth\]"),
    re.compile(r"check pass; user (?P<u>\S+)"),
    re.compile(r"authentication failure;.*\buser=(?P<u>\S+)\s*$"),
    re.compile(r"Disconnecting: Too many authentication failures for (?P<u>.+?) \[preauth\]"),
    re.compile(r"Accepted (?:password|publickey) for (?P<u>\S+) from"),
    re.compile(r"session (?:opened|closed) for user (?P<u>\S+)"),
]

# (pattern, event_type, ground_truth_triage) - first match wins.
RULES = [
    (re.compile(r"POSSIBLE BREAK-IN ATTEMPT"), "reverse_dns_mismatch", "suspicious"),
    (re.compile(r"Failed (password|none)"), "failed_login", "malicious"),
    (re.compile(r"Invalid user|invalid user"), "invalid_user", "malicious"),
    (re.compile(r"authentication failure"), "pam_auth_failure", "malicious"),
    (re.compile(r"Too many authentication failures|ignoring max retries"), "auth_retry_limit", "malicious"),
    (re.compile(r"check pass; user"), "pam_check_pass", "suspicious"),
    (re.compile(r"Did not receive identification string"), "no_ident_string", "suspicious"),
    (re.compile(r"Accepted (password|publickey)"), "successful_login", "benign"),
    (re.compile(r"session opened"), "session_opened", "benign"),
    (re.compile(r"session closed"), "session_closed", "benign"),
    (re.compile(r"Received disconnect|Connection closed|Disconnecting"), "disconnect", "benign"),
    (re.compile(r"fatal: Write failed"), "connection_error", "benign"),
]


def classify(msg: str):
    for pat, etype, label in RULES:
        if pat.search(msg):
            return etype, label
    return "other", "benign"


def extract_username(msg: str):
    for pat in USER_RES:
        m = pat.search(msg)
        if m:
            return m.group("u")
    return None


def parse_line(line: str, idx: int, year: int = YEAR):
    """Parse one raw line into an event dict, or None if it does not match."""
    line = line.rstrip("\r\n")
    m = LINE_RE.match(line)
    if not m:
        return None
    msg = m.group("msg")
    ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    ip = IP_RE.search(msg)
    port = PORT_RE.search(msg)
    etype, label = classify(msg)
    username = extract_username(msg)

    return {
        "event_id": f"ssh-{idx:06d}",
        "source": "ssh",
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "schema": {
            "host": m["host"],
            "process": m["proc"],
            "pid": int(m["pid"]),
            "src_ip": ip.group(1) if ip else None,
            "src_port": int(port.group(1)) if port else None,
            "event_type": etype,
        },
        "untrusted": {"username": username} if username is not None else {},
        "raw": line,
        "labels": {
            "injected": False,
            "payload_id": None,
            "payload_category": None,
            "target_field": None,
            "ground_truth_triage": label,
        },
    }


def load_events(path: Path = RAW_FILE, year: int = YEAR):
    events, skipped = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if not line.strip():
                continue
            ev = parse_line(line, i, year)
            if ev is None:
                skipped += 1
            else:
                events.append(ev)
    return events, skipped


def main():
    events, skipped = load_events()
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    from collections import Counter
    print(f"parsed {len(events)} events, skipped {skipped} -> {OUT_FILE}")
    print("triage labels:", dict(Counter(e["labels"]["ground_truth_triage"] for e in events)))
    print("event types:  ", dict(Counter(e["schema"]["event_type"] for e in events).most_common()))
    with_user = sum(1 for e in events if "username" in e["untrusted"])
    print(f"events with a username field (injectable): {with_user}/{len(events)}")


if __name__ == "__main__":
    main()