"""Cross-environment test data: Federated OCPP 1.6 dataset (Zenodo 14887131) pcaps -> our JSONL format.

Usage:
    python federated.py <pcap> <out_folder> --attack charging_profile|denial_of_charge

Real ABB Terra 54 + SteVe, plaintext OCPP, attacker present for the whole capture. Labels per message:
  charging_profile : every SetChargingProfile sent to the charger is the attack
  denial_of_charge : RemoteStartTransaction with random idTags is the attack, and so is every
                     transaction it starts (its StartTransaction, MeterValues, StopTransaction)
Everything else is labelled benign. The attacker's ARP spoofing makes each frame appear twice; duplicates
(same sender and text within 2 s) are dropped.
"""
import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

CHARGER_IP = "192.168.21.128"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("out", type=Path)
    ap.add_argument("--attack", required=True, choices=["charging_profile", "denial_of_charge"])
    args = ap.parse_args()

    rows = subprocess.run(["tshark", "-r", args.pcap, "-Y", "websocket.payload.text", "-T", "fields",
                           "-E", "separator=\t", "-E", "aggregator=\x1f", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "websocket.payload.text"],
                          capture_output=True, text=True, check=True).stdout.splitlines()
    seen, frames, attack_tags, attack_tx, pending = {}, [], set(), set(), {}
    messages = []                                           # one packet can carry several messages
    for row in rows:
        t, src, texts = row.split("\t", 2)
        messages += [(float(t), src, text) for text in texts.split("\x1f")]
    for t, src, text in messages:
        if seen.get((src, text), -9) > t - 2:
            continue                                        # same frame again (attacker in the middle)
        seen[(src, text)] = t
        msg = json.loads(text)
        label = "benign"
        if msg[0] == 2:
            action, payload = msg[2], msg[3]
            if args.attack == "charging_profile" and action == "SetChargingProfile":
                label = args.attack
            if args.attack == "denial_of_charge":
                if action == "RemoteStartTransaction":
                    attack_tags.add(payload["idTag"])
                    label = args.attack
                elif action == "StartTransaction" and payload["idTag"] in attack_tags:
                    pending[msg[1]] = True
                    label = args.attack
                elif payload.get("transactionId") in attack_tx:
                    label = args.attack
        elif msg[0] == 3 and pending.pop(msg[1], False):
            attack_tx.add(msg[2]["transactionId"])
            label = args.attack
        ts = datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        frames.append({"ts": ts, "src": "cp" if src == CHARGER_IP else "csms", "cp": "T54HU11121020",
                       "label": label, "msg": msg})

    args.out.mkdir(parents=True, exist_ok=True)
    with open(args.out / "T54HU11121020.jsonl", "w") as f:
        for frame in sorted(frames, key=lambda f: f["ts"]):
            f.write(json.dumps(frame, separators=(",", ":")) + "\n")
    labels = [f["label"] for f in frames]
    print(f"{len(frames)} frames:", {lab: labels.count(lab) for lab in set(labels)})


if __name__ == "__main__":
    main()
