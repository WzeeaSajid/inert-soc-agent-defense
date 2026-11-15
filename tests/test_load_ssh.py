import pytest
from attacks.generators.load_ssh import RAW_FILE, load_events, parse_line


def test_parse_failed_password_invalid_user():
    line = ("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user "
            "webmaster from 173.234.31.186 port 38926 ssh2\r\n")
    ev = parse_line(line, 0)
    assert ev["schema"]["src_ip"] == "173.234.31.186"
    assert ev["schema"]["src_port"] == 38926
    assert ev["untrusted"]["username"] == "webmaster"
    assert ev["labels"]["ground_truth_triage"] == "malicious"
    assert "\r" not in ev["raw"]


def test_disconnect_has_no_username():
    line = "Dec 10 07:07:38 LabSZ sshd[24206]: Received disconnect from 52.80.34.196: 11: Bye Bye [preauth]"
    ev = parse_line(line, 1)
    assert ev["untrusted"] == {}
    assert ev["labels"]["ground_truth_triage"] == "benign"


def test_garbage_line_returns_none():
    assert parse_line("not a syslog line", 2) is None


@pytest.mark.skipif(not RAW_FILE.exists(), reason="run data/download_datasets.py first")
def test_full_file_parses():
    events, skipped = load_events()
    assert skipped == 0
    assert len(events) >= 1900
    ids = [e["event_id"] for e in events]
    assert len(ids) == len(set(ids))
    for e in events:
        assert set(e) == {"event_id", "source", "timestamp", "schema", "untrusted", "raw", "labels"}