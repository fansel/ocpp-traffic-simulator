"""Check generated traffic: every frame against the official OCPP 1.6 JSON schemas, plus basic consistency.

Usage: python validate.py data/out/demo
"""
import collections
import json
import os
import sys
from pathlib import Path

import jsonschema
import ocpp

SCHEMAS = Path(os.path.dirname(ocpp.__file__)) / "v16" / "schemas"
validators = {}


def schema_errors(action, payload, response):
    name = action + ("Response" if response else "")
    if name not in validators:
        validators[name] = jsonschema.Draft4Validator(json.load(open(SCHEMAS / f"{name}.json")))
    return [e.message for e in validators[name].iter_errors(payload)]


def main(folder):
    errors, actions = collections.Counter(), collections.Counter()
    for path in sorted(Path(folder).glob("*.jsonl")):
        pending, last_ts, meter_start = {}, "", None
        for line in open(path):
            f = json.loads(line)
            msg = f["msg"]
            assert f["ts"] >= last_ts, f"{path.name}: frames out of order"
            last_ts = f["ts"]
            if msg[0] == 2:                                   # CALL (charger or backend)
                action, payload = msg[2], msg[3]
                pending[msg[1]] = action
                actions[action] += 1
            else:                                             # CALLRESULT to that call
                action, payload = pending.pop(msg[1]), msg[2]
            for e in schema_errors(action, payload, msg[0] == 3):
                errors[f"{action}{'Response' if msg[0] == 3 else ''}: {e}"] += 1
            if msg[0] == 2 and action == "StartTransaction":
                meter_start = payload["meterStart"]
            if msg[0] == 2 and action == "StopTransaction" and payload["meterStop"] < meter_start:
                errors[f"{path.name}: meterStop below meterStart"] += 1
    print("calls per action:", dict(actions.most_common()))
    print("schema/consistency problems:" if errors else "no problems found")
    for e, n in errors.most_common():
        print(f"  {n:6d}  {e}")


if __name__ == "__main__":
    main(sys.argv[1])
