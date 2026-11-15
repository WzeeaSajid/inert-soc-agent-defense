"""Download the seed datasets into data/raw/.

Usage:
    python data/download_datasets.py            # download everything automatable
    python data/download_datasets.py --only ssh # just one source

Sources:
    ssh   -> Loghub OpenSSH 2k sample (single file)
    evtx  -> EVTX-ATTACK-SAMPLES (shallow git clone)
    csic  -> CSIC 2010 must be downloaded manually (see message printed below)
"""
import argparse
import subprocess
import urllib.request
from pathlib import Path

RAW = Path(__file__).resolve().parent / "raw"

SSH_URL = "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log"
EVTX_REPO = "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git"


def get_ssh():
    dest = RAW / "ssh" / "OpenSSH_2k.log"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        print(f"[ssh] already present: {dest}")
        return
    print("[ssh] downloading Loghub OpenSSH 2k sample ...")
    urllib.request.urlretrieve(SSH_URL, dest)
    print(f"[ssh] saved {dest} ({dest.stat().st_size} bytes)")


def get_evtx():
    dest = RAW / "evtx" / "EVTX-ATTACK-SAMPLES"
    if dest.exists():
        print(f"[evtx] already present: {dest}")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    print("[evtx] shallow-cloning EVTX-ATTACK-SAMPLES ...")
    subprocess.run(["git", "clone", "--depth", "1", EVTX_REPO, str(dest)], check=True)
    commit = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    (dest.parent / "EVTX_COMMIT.txt").write_text(commit + "\n")
    print(f"[evtx] done, commit {commit}")


def csic_instructions():
    print(
        "[csic] CSIC 2010 is not auto-downloaded (host/mirrors change).\n"
        "       Download the HTTP dataset 2010 (normalTrafficTraining, normalTrafficTest,\n"
        "       anomalousTrafficTest) and place the text files in data/raw/csic2010/"
    )
    (RAW / "csic2010").mkdir(parents=True, exist_ok=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--only", choices=["ssh", "evtx", "csic"])
    args = p.parse_args()
    steps = {"ssh": get_ssh, "evtx": get_evtx, "csic": csic_instructions}
    for name, fn in steps.items():
        if args.only in (None, name):
            fn()


if __name__ == "__main__":
    main()
