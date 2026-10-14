# OCPP Traffic Simulator

Turns real EV charging sessions ([ACN-Data](https://ev.caltech.edu/dataset)) into benign OCPP 1.6J traffic, injects
labelled attacks for test sets, and trains a benign-only anomaly detector (LSTM autoencoder). See `PLAN.md` for design
decisions and `docs/findings.tex` for results.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install numpy torch jsonschema ocpp
```

## Get an ACN-Data API token

1. Go to <https://ev.caltech.edu/dataset> and click **Sign up** (or log in).
2. Open the **API** page / your account page and generate an **API token**.
3. Give the token to `fetcher.py` in one of three ways:
   - `export ACN_TOKEN=<token>`
   - a `.env` file in the repo root containing `ACN_TOKEN=<token>` (git-ignored)
   - `python fetcher.py --token <token>`

## Pipeline

```bash
# 1. Download sessions -> data/raw/acn_<site>.jsonl (resumable; sites: caltech, jpl, office001)
python fetcher.py --sites jpl --start 2019-01-01 --end 2019-04-01

# 2. Benign OCPP traffic -> one JSONL per charger
python generator.py --site jpl --start 2019-03-04 --end 2019-03-11 --stations 10 --out data/out/demo
python validate.py data/out/demo            # check against official OCPP 1.6 JSON schemas

# 3. Labelled attack test set (billing_fraud, cloned_card, dos_flood, spoofing, ...)
python attacks.py --site jpl --start 2019-03-15 --end 2019-03-22 --out data/out/attack_test

# 4. Features
python features.py data/out/train train.npz
python features.py data/out/test  test.npz --like train.npz

# 5. Train + evaluate (GPU recommended; see train.sbatch for a SLURM example)
python train.py features/train.npz features/val.npz features/test.npz --out results/

# 6. Optional: per-message cross-evaluation, and real-world test data
python crosseval.py crosseval/a2 --train features/train.npz --val features/val.npz --model results/model.pt
python federated.py <pcap> <out_folder> --attack charging_profile   # Federated OCPP dataset, Zenodo 14887131
```

`data/` (raw downloads and generated traffic) is not part of the repository; regenerate it with the steps above.
Each script's docstring lists its full options.
