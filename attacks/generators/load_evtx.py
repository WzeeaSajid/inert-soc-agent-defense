"""Load EVTX-ATTACK-SAMPLES and convert process-creation events to INERT events.

Run from the repo root:
    python -m attacks.generators.load_evtx

Output: data/interim/evtx_clean.jsonl  (clean events, no payloads yet)

Design notes / assumptions (document these in the report):
- Only Sysmon Event ID 1 (process creation) is used. Security 4688 events in this
  dataset have an empty CommandLine (command-line auditing was off), so they are dropped.
- Events with an empty CommandLine are dropped (nothing to ablate or inject into).
- Identical (Image, CommandLine) pairs are capped at MAX_DUP to stop ping sweeps etc.
  from dominating the corpus.
- CommandLine and ParentCommandLine are attacker-controlled -> `untrusted`.
  Image / ParentImage are kept in `schema` (needed to identify the process) even
  though executable names can be attacker-chosen; recorded as a known limitation.
- ground_truth_triage is rule-based (RULES below), not annotated by dataset authors.
- `raw` is a single-line JSON rendering of the event (like a Winlogbeat/forwarder
  record). Use render_raw() to rebuild it after an injection changes a field.
"""
import glob
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path

from Evtx.Evtx import Evtx

ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = ROOT / "data" / "raw" / "evtx" / "EVTX-ATTACK-SAMPLES"
OUT_FILE = ROOT / "data" / "interim" / "evtx_clean.jsonl"
MAX_DUP = 3
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

I = re.IGNORECASE
MALICIOUS = [re.compile(p, I) for p in [
    r"powershell.*(-e\b|-enc|-encodedcommand|-nop|-noni|-w(indowstyle)?\s+hidden|iex|invoke-|downloadstring|frombase64string|bypass)",
    r"mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs.*minidump",
    r"certutil.*(-urlcache|-decode|-encode)",
    r"bitsadmin.*(/transfer|/addfile)",
    r"reg(\.exe)?\s+(add|save|import)\b",
    r"schtasks.*/create",
    r"vssadmin.*delete|wmic.*shadowcopy.*delete",
    r"net1?\s+(user|localgroup)\s.*(/add|administrators)",
    r"rundll32.*(javascript|vbscript|\.dll,\s*#|shell32.*control_rundll)",
    r"regsvr32.*(/i:|scrobj|http)",
    r"mshta.*(http|vbscript|javascript)",
    r"wmic.*(process\s+call\s+create|/node)",
    r"\bsc(\.exe)?\s+(create|config)\b",
    r"msbuild.*\.(xml|csproj)|installutil|regasm|regsvcs|cmstp|odbcconf",
    r"uacme|malseclogon|\bpoc\.exe|promptforcredential",
    r"netsh.*(portproxy|advfirewall|add\s+helper)",
    r"icacls.*/grant|takeown|sdbinst|wusa.*/extract",
]]
SUSPICIOUS = [re.compile(p, I) for p in [
    r"\bwhoami\b|\bipconfig\b|\bsysteminfo\b|\btasklist\b|\bnltest\b|\barp\s+-a\b|\bnetstat\b",
    r"\bnet1?\s+(view|user|group|share|use|accounts|session)\b",
    r"\breg(\.exe)?\s+query\b|\bsc(\.exe)?\s+query\b",
    r"\bping(\.exe)?\s",
    r"\bwmic\b|\battrib\b|\bicacls\b|\bpowershell\b|\bcmd(\.exe)?\"?\s+/c\b",
]]
BENIGN_IMAGES = {
    "svchost.exe", "consent.exe", "ui0detect.exe", "conhost.exe", "wlms.exe",
    "flashplayerupdateservice.exe", "calc.exe", "notepad.exe", "timeout.exe",
    "firefox.exe", "werfault.exe", "filecoauth.exe", "taskhost.exe", "taskhostw.exe",
    "mobsync.exe", "smss.exe", "logonui.exe", "explorer.exe", "mmc.exe",
}


def classify(image: str, cmd: str):
    for p in MALICIOUS:
        if p.search(cmd):
            return "malicious"
    for p in SUSPICIOUS:
        if p.search(cmd):
            return "suspicious"
    if image.replace("/", "\\").split("\\")[-1].lower() in BENIGN_IMAGES:
        return "benign"
    return "suspicious"  # unknown binary seen in an attack capture


def render_raw(schema: dict, untrusted: dict) -> str:
    """Single-line JSON rendering of a process-creation event."""
    rec = {
        "EventID": schema["event_id"],
        "Channel": schema["channel"],
        "Computer": schema["computer"],
        "EventData": {
            "User": schema["user"],
            "ProcessId": schema["process_id"],
            "Image": schema["image"],
            "ParentImage": schema["parent_image"],
            "CommandLine": untrusted.get("CommandLine", ""),
            "ParentCommandLine": untrusted.get("ParentCommandLine", ""),
        },
    }
    return json.dumps(rec, ensure_ascii=False)


def _iso(utc_time: str) -> str:
    # Sysmon UtcTime: "2019-04-29 04:38:33.152"
    try:
        return datetime.strptime(utc_time[:19], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return utc_time


def iter_process_events(root: Path = RAW_DIR):
    """Yield (relative_file, system_dict, eventdata_dict) for Sysmon EID 1 events."""
    for f in sorted(glob.glob(str(root / "**" / "*.evtx"), recursive=True)):
        rel = Path(f).relative_to(root).as_posix()
        try:
            with Evtx(f) as log:
                for rec in log.records():
                    try:
                        r = ET.fromstring(rec.xml())
                    except Exception:
                        continue
                    eid = r.findtext("e:System/e:EventID", namespaces=NS)
                    chan = r.findtext("e:System/e:Channel", namespaces=NS) or ""
                    if eid != "1" or "Sysmon" not in chan:
                        continue
                    system = {
                        "channel": chan,
                        "computer": r.findtext("e:System/e:Computer", namespaces=NS) or "",
                    }
                    data = {d.get("Name"): (d.text or "") for d in r.findall("e:EventData/e:Data", NS)}
                    yield rel, system, data
        except Exception as exc:  # corrupt file: skip, but say so
            print(f"[warn] could not read {rel}: {exc}")


def build_event(idx: int, rel: str, system: dict, data: dict) -> dict:
    schema = {
        "event_id": 1,
        "channel": system["channel"],
        "computer": system["computer"],
        "user": data.get("User", ""),
        "process_id": data.get("ProcessId", ""),
        "image": data.get("Image", ""),
        "parent_image": data.get("ParentImage", ""),
        "event_type": "process_creation",
        "source_file": rel,
    }
    untrusted = {"CommandLine": data.get("CommandLine", "")}
    if data.get("ParentCommandLine"):
        untrusted["ParentCommandLine"] = data["ParentCommandLine"]
    return {
        "event_id": f"evtx-{idx:06d}",
        "source": "windows_event",
        "timestamp": _iso(data.get("UtcTime", "")),
        "schema": schema,
        "untrusted": untrusted,
        "raw": render_raw(schema, untrusted),
        "labels": {
            "injected": False,
            "payload_id": None,
            "payload_category": None,
            "target_field": None,
            "ground_truth_triage": classify(schema["image"], untrusted["CommandLine"]),
        },
    }


def load_events(root: Path = RAW_DIR, max_dup: int = MAX_DUP):
    events, seen = [], Counter()
    stats = Counter()
    for rel, system, data in iter_process_events(root):
        stats["sysmon1_total"] += 1
        cmd = data.get("CommandLine", "")
        if not cmd.strip():
            stats["dropped_empty_cmdline"] += 1
            continue
        key = (data.get("Image", "").lower(), cmd)
        seen[key] += 1
        if seen[key] > max_dup:
            stats["dropped_duplicates"] += 1
            continue
        events.append(build_event(len(events), rel, system, data))
    stats["kept"] = len(events)
    return events, stats


def main():
    if not RAW_DIR.exists():
        raise SystemExit("EVTX samples not found. Run: python data/download_datasets.py")
    events, stats = load_events()
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    print(f"wrote {len(events)} events -> {OUT_FILE}")
    print("stats:", dict(stats))
    print("triage labels:", dict(Counter(e["labels"]["ground_truth_triage"] for e in events)))
    lens = sorted(len(e["untrusted"]["CommandLine"]) for e in events)
    print(f"CommandLine length: median {lens[len(lens)//2]}, max {lens[-1]}")


if __name__ == "__main__":
    main()