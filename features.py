"""Messages -> vendor-independent feature windows for the model.

Usage:
    python features.py data/out/train train.npz                       # builds vocabulary + charger registry
    python features.py data/out/test  test.npz --like train.npz       # reuses them

Only requests are used (charger calls and backend calls); SteVe's answers carry no charger behaviour.
Each request becomes one token (what happened) and a few numbers (how much / how fast). Vendor format
(message IDs, timestamp style, info texts, units, phase layout) is removed so the model sees behaviour only.

Per request: token = action (+ status / meter context / error flag), numbers =
  log(1 + seconds since this charger's previous request), energy since previous reading (kWh),
  power (kW), current (A/32), offered current (A/32), session energy at stop (kWh),
  idTag in use at another charger (0/1), boot fingerprint differs from the registered one (0/1),
  transactionId not open on this charger (0/1)
"""
import argparse
import heapq
import json
import math
from datetime import datetime
from pathlib import Path

import numpy as np

WINDOW, STRIDE = 64, 16


def reading(meter_value):
    """Sum a MeterValues payload into (energy Wh, power W, current A, offered A) whatever the vendor's layout."""
    e = p = i = o = None
    for sv in meter_value[0]["sampledValue"]:
        value, kilo = float(sv["value"]), sv.get("unit", "").startswith("k")
        m = sv.get("measurand", "Energy.Active.Import.Register")
        if m == "Energy.Active.Import.Register":
            e = value * (1000 if kilo else 1)
        elif m == "Power.Active.Import":
            p = (p or 0) + value * (1000 if kilo else 1)
        elif m == "Current.Import":
            i = (i or 0) + value
        elif m == "Current.Offered":
            o = value
        elif m == "Power.Offered":
            o = value / 208                          # W -> A (fixed nominal voltage is fine for a feature)
    return e, p, i, o


def events(folder):
    """All frames of all chargers in time order (lines start with the timestamp)."""
    files = [open(f) for f in sorted(Path(folder).glob("*.jsonl"))]
    return (json.loads(line) for line in heapq.merge(*files))


def extract(folder, registry):
    """Per charger: list of (token, numbers, label)."""
    seqs, last_t, open_tx, pending, tags, last_e = {}, {}, {}, {}, {}, {}
    learn = registry is None
    registry = {} if learn else registry
    for f in events(folder):
        cp, msg = f["cp"], f["msg"]
        t = datetime.fromisoformat(f["ts"].replace("Z", "+00:00")).timestamp()
        if msg[0] == 3:                                   # answers: only needed to learn transaction IDs
            start = pending.pop((cp, msg[1]), None)
            if start and "transactionId" in msg[2]:
                open_tx.setdefault(cp, {})[msg[2]["transactionId"]] = start
            continue
        action, pl = msg[2], msg[3]
        nums = [math.log1p(t - last_t.get(cp, t)), 0, 0, 0, 0, 0, 0, 0, 0]
        last_t[cp] = t
        token = action
        tag = pl.get("idTag")
        if tag and any(c != cp for c in tags.get(tag, ())):
            nums[6] = 1                                   # same card active at another charger
        if action == "StatusNotification":
            token += "/" + pl["status"] + ("/error" if pl["errorCode"] != "NoError" else "")
        elif action == "BootNotification":
            fp = (pl["chargePointVendor"], pl["chargePointModel"], pl.get("firmwareVersion"))
            if learn:
                registry.setdefault(cp, fp)
            nums[7] = float(cp in registry and registry[cp] != fp)
        elif action == "StartTransaction":
            pending[(cp, msg[1])] = (tag, pl["meterStart"])
            tags.setdefault(tag, set()).add(cp)
        elif action == "MeterValues":
            context = pl["meterValue"][0]["sampledValue"][0].get("context", "Sample.Periodic")
            token += "/" + context
            e, p, i, o = reading(pl["meterValue"])
            tx = pl.get("transactionId")
            if tx is not None and pl["connectorId"] != 0 and context != "Sample.Clock":  # clock readings report
                if tx not in open_tx.get(cp, {}):                                      # a past interval
                    nums[8] = 1
                if e is not None:
                    nums[1] = (e - last_e.get((cp, tx), e)) / 1000
                    last_e[(cp, tx)] = e
            nums[2:5] = [(p or 0) / 1000, (i or 0) / 32, (o or 0) / 32]
        elif action == "StopTransaction":
            start = open_tx.get(cp, {}).pop(pl["transactionId"], None)
            if start is None:
                nums[8] = 1                               # stop for a transaction that is not running here
            else:
                nums[5] = (pl["meterStop"] - start[1]) / 1000
                tags.get(start[0], set()).discard(cp)
        seqs.setdefault(cp, []).append((token, nums, f["label"]))
    return seqs, registry


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder")
    ap.add_argument("out")
    ap.add_argument("--like", help="npz from the training set: reuse its vocabulary and charger registry")
    ap.add_argument("--stride", type=int, default=STRIDE)
    args = ap.parse_args()

    like = np.load(args.like, allow_pickle=True) if args.like else None
    registry = like["registry"].item() if like is not None else None
    seqs, registry = extract(args.folder, registry)
    vocab = list(like["vocab"]) if like is not None else ["<unk>"] + sorted({tok for s in seqs.values() for tok, _, _ in s})
    index = {tok: k for k, tok in enumerate(vocab)}

    tokens, nums, labels, chargers = [], [], [], []
    for cp, seq in seqs.items():
        for k in range(0, len(seq) - WINDOW + 1, args.stride):
            window = seq[k:k + WINDOW]
            tokens.append([index.get(tok, 0) for tok, _, _ in window])
            nums.append([n for _, n, _ in window])
            attack = [lab for _, _, lab in window if lab != "benign"]
            labels.append(attack[0] if attack else "benign")   # a window is malicious if any message is
            chargers.append(cp)
    np.savez_compressed(args.out, tokens=np.array(tokens, np.int16), nums=np.array(nums, np.float32),
                        labels=np.array(labels), chargers=np.array(chargers), vocab=np.array(vocab),
                        registry=np.array(registry, dtype=object))
    print(f"{len(tokens)} windows, vocabulary {len(vocab)},", dict(zip(*np.unique(labels, return_counts=True))))


if __name__ == "__main__":
    main()
