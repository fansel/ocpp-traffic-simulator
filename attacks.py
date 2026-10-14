"""Labelled test traffic: benign traffic plus injected attacks, produced by the same generator.

Usage:
    python attacks.py --site jpl --start 2019-03-15 --end 2019-03-22 --out data/out/attack_test

Every frame carries "label": "benign" or the attack name. Attacks reuse the profile, message IDs and timing
of the attacked charger, so the only difference to benign traffic is the manipulation itself.

  billing_fraud : meter tampering, one session reports only 50-80 % of the energy
  cloned_card   : a user's card is used at a second charger while their own session is running
  dos_flood     : a compromised charger floods the backend with Heartbeat or StatusNotification
  spoofing      : a device with another vendor fingerprint connects under an existing charger ID
  replay        : a recorded StopTransaction is sent again hours later
"""
import argparse
import collections
import random
from datetime import datetime, timezone
from pathlib import Path

import generator as g
from profiles import PROFILES

ATTACKS = ["billing_fraud", "cloned_card", "dos_flood", "spoofing", "replay"]


def profile_of(name, seed):
    """Profile the generator will give this charger (first draw of its random generator in build_all)."""
    return random.Random(f"{seed}-{name}").choice(list(PROFILES))


def cloned_card(stations, names, rng, seed):
    """Copy a real session (with its measured curve) to another, idle charger, using a victim's card."""
    victims = [(n, s) for n in names for s in stations[n] if s["user"]]
    n, victim = rng.choice(victims)
    donor = rng.choice([s for m in names for s in stations[m]])
    conn = victim["conn"] + rng.uniform(600, 3600)            # while the victim is still charging
    shift = conn - donor["conn"]
    fake = {"conn": conn, "done": donor["done"] and donor["done"] + shift, "disc": donor["disc"] + shift,
            "kwh": donor["kwh"], "user": victim["user"], "label": "cloned_card",
            "series": donor["series"] and {**donor["series"], "t": [x + shift for x in donor["series"]["t"]]}}
    for m in rng.sample(names, len(names)):                    # a charger that identifies users and is free
        free = all(s["disc"] + 60 < fake["conn"] or s["conn"] > fake["disc"] + 60 for s in stations[m])
        if m != n and free and PROFILES[profile_of(m, seed)]["start"] != "freevend":
            stations[m].append(fake)
            stations[m].sort(key=lambda s: s["conn"])
            return m
    return None


def billing_fraud(cp, rng):
    """Scale energy, power and current of one transaction (and its meterStop) down by the same factor."""
    starts = [c for c in cp.calls if c["action"] == "StartTransaction" and c["label"] == "benign"]
    if not starts:
        return False
    start, factor = rng.choice(starts), rng.uniform(0.5, 0.8)
    tx, base = start["tx"], start["payload"]["meterStart"]
    start["label"] = "billing_fraud"
    for c in cp.calls:
        p = c["payload"]
        if c["src"] != "cp" or p.get("transactionId") != tx or c["action"] not in ("MeterValues", "StopTransaction"):
            continue
        c["label"] = "billing_fraud"
        if c["action"] == "StopTransaction":
            p["meterStop"] = base + round((p["meterStop"] - base) * factor)
        for mv in p.get("meterValue", []):
            for sv in mv["sampledValue"]:
                if sv["measurand"].startswith(("Energy", "Power.Active", "Current.Import")):
                    value, decimals = float(sv["value"]), len(sv["value"].partition(".")[2])
                    if sv["measurand"] == "Energy.Active.Import.Register":
                        value = base + (value - base) * factor   # lifetime registers: scale only this session
                    else:
                        value *= factor
                    sv["value"] = f"{value:.{decimals}f}"
    return True


def dos_flood(cp, rng, a, b):
    """1-5 minutes of 5-20 requests per second (the one-call-at-a-time rule caps the real rate)."""
    t0, rate, action = rng.uniform(a, b - 3600), rng.uniform(5, 20), rng.choice(["Heartbeat", "StatusNotification"])
    cp.label = "dos_flood"
    for k in range(int(rng.uniform(60, 300) * rate)):
        if action == "Heartbeat":
            cp.call(t0 + k / rate, "Heartbeat", {})
        else:
            cp.status(t0 + k / rate, "Available")
    cp.label = "benign"
    return True


def spoofing(cp, rng, a, b, seed):
    """A second device boots under the same charger ID with another vendor's fingerprint, stays 10-60 min."""
    fake = g.Charger(cp.id, rng.choice([p for p in PROFILES if p != cp.profile]), random.Random(f"{seed}-spoof-{cp.id}"))
    fake.label = "spoofing"
    t0 = rng.uniform(a, b - 7200)
    fake.boot(t0)
    fake.heartbeats(t0, t0 + rng.uniform(600, 3600))
    return fake.frames()


def replay(cp, rng, b):
    """Re-send a recorded StopTransaction 1-24 h later (old timestamp, transaction already closed)."""
    stops = [c for c in cp.calls if c["action"] == "StopTransaction" and c["t"] + 86400 < b]
    if not stops:
        return False
    old = rng.choice(stops)
    cp.label = "replay"
    cp.call(old["t"] + rng.uniform(3600, 86400), "StopTransaction", dict(old["payload"]), queue=True)
    cp.label = "benign"
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--site", default="jpl", choices=["caltech", "jpl", "office001"])
    ap.add_argument("--start", required=True, help="YYYY-MM-DD (UTC)")
    ap.add_argument("--end", required=True, help="YYYY-MM-DD (UTC), exclusive")
    ap.add_argument("--per-day", type=float, default=2, help="attacks per day on the whole site")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    a = datetime.fromisoformat(args.start).replace(tzinfo=timezone.utc).timestamp()
    b = datetime.fromisoformat(args.end).replace(tzinfo=timezone.utc).timestamp()
    stations = g.load_sessions(f"data/raw/acn_{args.site}.jsonl", a, b, g.load_measured(f"data/raw/acn_{args.site}_ts.jsonl"))
    names = sorted(stations)
    rng = random.Random(f"attacks-{args.seed}")
    plan = [rng.choice(ATTACKS) for _ in range(round((b - a) / 86400 * args.per_day))]

    done = []
    for _ in range(plan.count("cloned_card")):         # fake sessions must exist before transactions are numbered
        done.append(("cloned_card", cloned_card(stations, names, rng, args.seed)))
    chargers = g.build_all(stations, names, a, b, args.seed)
    extra = collections.defaultdict(list)                # frames of spoofing devices
    for attack in plan:
        n = rng.choice(names)
        cp = chargers[n]
        if attack == "billing_fraud":
            ok = billing_fraud(cp, rng)
        elif attack == "dos_flood":
            ok = dos_flood(cp, rng, a, b)
        elif attack == "spoofing":
            extra[n] += spoofing(cp, rng, a, b, args.seed)
            ok = True
        elif attack == "replay":
            ok = replay(cp, rng, b)
        else:
            continue
        done.append((attack, n if ok else None))

    args.out.mkdir(parents=True, exist_ok=True)
    labels = collections.Counter()
    for n, cp in chargers.items():
        frames = sorted(cp.frames() + extra[n], key=lambda f: f[0])
        labels.update(f[3] for f in frames)
        g.write(args.out / f"{n}.jsonl", n, frames)
    for attack, n in done:
        print(f"{attack:14s} -> {n or 'skipped (no suitable target)'}")
    print("frames per label:", dict(labels.most_common()))


if __name__ == "__main__":
    main()
