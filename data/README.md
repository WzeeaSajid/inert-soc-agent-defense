# data/

- `download_datasets.py` - fetches seed datasets into `raw/` (git-ignored)
- `raw/` - downloaded sources (Loghub OpenSSH, EVTX-ATTACK-SAMPLES, CSIC 2010)
- `corpus/` - final labeled, versioned corpus (JSONL + manifest)

Run from the repo root:
    python data/download_datasets.py
CSIC 2010 must be downloaded manually into `raw/csic2010/`.
