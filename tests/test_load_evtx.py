import json
import pytest
from attacks.generators.load_evtx import RAW_DIR, build_event, classify, load_events, render_raw


def test_classify_examples():
    assert classify("C:\\Windows\\system32\\svchost.exe", "svchost.exe -k netsvcs") == "benign"
    assert classify("C:\\x\\cmd.exe", "cmd /c procdump.exe -ma lsass.exe d.dmp") == "malicious"
    assert classify("C:\\Windows\\system32\\ping.exe", "ping -n 1 192.168.1.5") == "suspicious"
    assert classify("C:\\x\\powershell.exe", "powershell -nop -w hidden -enc AAAA") == "malicious"


def test_build_event_and_raw_roundtrip():
    system = {"channel": "Microsoft-Windows-Sysmon/Operational", "computer": "PC01"}
    data = {"UtcTime": "2019-04-29 04:38:33.152", "User": "PC01\\bob", "ProcessId": "42",
            "Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami /all",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentCommandLine": "cmd.exe"}
    ev = build_event(0, "x.evtx", system, data)
    assert ev["timestamp"] == "2019-04-29T04:38:33Z"
    assert ev["untrusted"]["CommandLine"] == "whoami /all"
    assert ev["labels"]["injected"] is False
    parsed = json.loads(ev["raw"])
    assert parsed["EventData"]["CommandLine"] == "whoami /all"
    # raw must be rebuildable after an injection edits an untrusted field
    ev["untrusted"]["CommandLine"] = "whoami /all PAYLOAD"
    assert "PAYLOAD" in render_raw(ev["schema"], ev["untrusted"])


@pytest.mark.skipif(not RAW_DIR.exists(), reason="run data/download_datasets.py first")
def test_full_run():
    events, stats = load_events()
    assert len(events) > 1000
    assert all(e["untrusted"]["CommandLine"].strip() for e in events)
    assert len({e["event_id"] for e in events}) == len(events)
    assert {e["labels"]["ground_truth_triage"] for e in events} == {"benign", "suspicious", "malicious"}