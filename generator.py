"""Turn real ACN charging sessions into benign OCPP 1.6J traffic, as seen by the backend (SteVe).

Usage:
    python generator.py --site jpl --start 2019-03-04 --end 2019-03-11 --stations 10 --out data/out/demo

Writes one file per charger: <out>/<chargerId>.jsonl, one WebSocket frame per line:
    {"ts": "...", "src": "cp"|"csms", "cp": "<id>", "label": "benign"|<attack>, "msg": [2|3, msgId, ...]}
Lines start with the timestamp, so `sort -m <out>/*.jsonl` gives the backend's interleaved view.

Each charger is simulated independently on a virtual clock in four steps:
  1. calls    : charger->backend requests at their event time (sessions, idle events)
  2. heartbeat: fill quiet periods with Heartbeats
  3. outages  : connection drops; transaction messages are queued, the rest is lost
  4. wire     : one outstanding call at a time, network delay, SteVe's exact responses
"""
import argparse
import bisect
import hashlib
import json
import math
import random
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from profiles import NET_RTT, PROFILES, SERVER_MEDIAN, SERVER_SIGMA

HEARTBEAT = 60          # interval SteVe sends in BootNotification.conf; 60 s in both real captures (CICEVSE, Federated)
FREQUENCY = 60          # Hz, US grid (ACN sites)
VOLTAGE = 208           # ACN sites supply EVSEs at 208 V (ACN-Data paper)
MAX_POWER = 6656        # W, 32 A x 208 V, typical ACN Level-2 EVSE
TAPER = 0.1             # ASSUMPTION: fallback curve only (no measured series): last 10 % ramps down linearly
# Rare benign events. ASSUMPTION: rates are placeholders until calibrated with real logs.
OUTAGE_PER_DAY, REBOOT_PER_DAY, FAULT_PER_DAY, BAD_CARD = 1 / 7, 1 / 14, 1 / 30, 0.03
FAULT_CODES = ["GroundFailure", "OverCurrentFailure", "HighTemperature", "PowerMeterFailure", "OtherError"]


def epoch(s):
    return parsedate_to_datetime(s).timestamp() if s else None


def iso(t, style="ms"):
    d = datetime.fromtimestamp(t, timezone.utc)
    if style == "us":
        return d.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if style == "s":
        return d.strftime("%Y-%m-%dT%H:%M:%SZ")
    if style in ("s000", "s001"):                       # ABB: always ".000Z", Grizzl-E: always ".001Z"
        return d.strftime("%Y-%m-%dT%H:%M:%S.") + style[1:] + "Z"
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def id_tag(user):
    """Same ACN user -> same RFID card: 4-byte UID as 8 hex chars."""
    return hashlib.sha1(str(user).encode()).hexdigest()[:8].upper()


def poisson_times(rng, a, b, per_day):
    """Random event times in [a, b) with on average `per_day` events per day."""
    t = a + rng.expovariate(per_day / 86400)
    while t < b:
        yield t
        t += rng.expovariate(per_day / 86400)


class ChargePlan:
    """Power curve of one session: constant power P, then a linear ramp to 0. Integrates exactly to kWhDelivered."""

    def __init__(self, t_start, t_done, t_disc, kwh):
        avail = t_disc - t_start
        d = (t_done or t_disc) - t_start
        d = max(d, kwh * 3.6e6 / (MAX_POWER * (1 - TAPER / 2)))  # not faster than the EVSE can deliver
        self.d = max(min(d, avail), 1)                            # but the car leaves at disconnectTime
        self.p = kwh * 3.6e6 / (self.d * (1 - TAPER / 2))         # W
        self.a = (1 - TAPER) * self.d                             # end of constant-power phase
        self.volt, self.pauses = VOLTAGE, []

    def offered(self, x):
        return MAX_POWER / VOLTAGE                                # 32 A, no smart charging in the fallback

    def power(self, x):
        if x <= self.a:
            return self.p
        return max(self.p * (1 - (x - self.a) / (TAPER * self.d)), 0)

    def energy(self, x):  # Wh delivered after x seconds
        x = min(x, self.d)
        y = max(x - self.a, 0)
        joule = self.p * min(x, self.a) + self.p * y - self.p * y * y / (2 * TAPER * self.d)
        return joule / 3600


class MeasuredPlan:
    """Power curve from ACN's measured charging current (one sample every ~4 s, fetcher.py --ts)."""

    def __init__(self, t_start, series, kwh):
        self.t, self.i, self.pilot = [x - t_start for x in series["t"]], series["i"], series["p"]
        self.ah = [0.0]                                           # cumulative ampere-hours at each sample
        for k in range(1, len(self.t)):
            self.ah.append(self.ah[-1] + self.i[k - 1] * (self.t[k] - self.t[k - 1]) / 3600)
        self.volt = kwh * 1000 / self.ah[-1] if self.ah[-1] else VOLTAGE  # ~203 V; makes energy match kWhDelivered
        on = [k for k, a in enumerate(self.i) if a > 0.5]
        self.d = self.t[on[-1]] if on else 1                      # last moment current was flowing
        self.pauses = []                                          # >= 2 min without current while charging
        k = on[0] if on else len(self.i)
        while on and k < on[-1]:
            j = k
            while self.i[j] <= 0.5:
                j += 1
            if self.t[j] - self.t[k] >= 120:                      # station paused (pilot 0) or the car did
                self.pauses.append((self.t[k], self.t[j], "SuspendedEVSE" if self.pilot[k] == 0 else "SuspendedEV"))
            k = j + 1

    def k(self, x):
        return max(bisect.bisect_right(self.t, x) - 1, 0)

    def power(self, x):
        return self.i[self.k(x)] * self.volt

    def energy(self, x):
        return self.ah[self.k(x)] * self.volt

    def offered(self, x):
        return self.pilot[self.k(x)]                              # ACN scheduler's current limit (pilot signal)


class Charger:
    def __init__(self, cp_id, profile, rng):
        self.id, self.profile, self.p, self.rng = cp_id, profile, PROFILES[profile], rng
        self.calls = []                              # dicts: t, src, action, payload, queue, auth, tx, label
        self.label = "benign"                        # attacks.py sets this while it injects messages
        self.meter0 = self.meter = rng.randint(100_000, 5_000_000)  # Wh already on the lifetime register
        self.sessions = []                           # (start, end, tx, plan) for clock-aligned readings
        self.drift = rng.uniform(0, 0.35)            # [FED] clock 0 ... +0.33 s off (drifts +25 ppm, reset at boot)
        self.serial = str(rng.randint(100000, 999999)) if self.p["serial_digits"] else f"{rng.getrandbits(40):010x}"

    def ts(self, t):
        return iso(t + self.drift, self.p["ts_style"])

    def call(self, t, action, payload, queue=False, auth="Accepted", tx=None, src="cp"):
        self.calls.append({"t": t, "src": src, "action": action, "payload": payload, "queue": queue,
                           "auth": auth, "tx": tx, "label": self.label})

    def status(self, t, status, connector=1, error="NoError"):
        payload = {"connectorId": connector, "errorCode": error, "status": status, **self.p["status_extra"]}
        if status in self.p["status_info"]:
            payload["info"] = self.p["status_info"][status]
        if self.p["status_has_timestamp"]:
            payload["timestamp"] = self.ts(t)
        self.call(t, "StatusNotification", payload)

    # ---- step 1: calls -------------------------------------------------------------------------
    def boot(self, t):
        rssi = self.rng.randint(9, 83)
        self.call(t, "BootNotification", {k: v.format(serial=self.serial, rssi=rssi) for k, v in self.p["boot"].items()})
        if self.rng.random() < self.p["boot_fault"]:  # Wallbox: sometimes Faulted first, Available ~30 s later
            for c in self.p["boot_connectors"]:
                self.status(t + 5, "Faulted", c, "InternalError")
            t += 30
        for c in self.p["boot_connectors"]:
            self.status(t + 0.5, "Available", c)

    def session(self, s, tx):
        rng, p = self.rng, self.p
        self.label = s.get("label", "benign")                   # attacks.py adds labelled fake sessions
        t = s["conn"] + rng.random()                            # ACN stores whole seconds; real events are not
        self.status(t, "Preparing")
        tag = id_tag(s["user"]) if s["user"] and p["start"] != "freevend" else self.serial  # no user: charger's own tag
        if tag != self.serial and p["start"] == "rfid":
            t += rng.lognormvariate(math.log(15), 0.6)          # ASSUMPTION: ~15 s until the card is tapped
            if rng.random() < BAD_CARD:                         # wrong card first, then the right one
                self.call(t, "Authorize", {"idTag": id_tag(rng.random())}, auth="Invalid")
                t += rng.uniform(10, 40)
            self.call(t, "Authorize", {"idTag": tag})
            t += rng.uniform(1, 3)
        elif tag != self.serial:                                # "app": backend sends RemoteStartTransaction
            t += rng.lognormvariate(math.log(15), 0.6)          # ASSUMPTION: ~15 s until started in the app
            self.call(t, "RemoteStartTransaction", {"connectorId": 1, "idTag": tag}, src="csms")
            t += rng.uniform(6.0, 7.1)                          # [FED] RemoteStart -> StartTransaction p5..p95
        elif p["start"] == "freevend":                          # [HA#176] Grizzl-E authorizes itself after 1-2 s
            t += rng.uniform(1, 2)
            self.call(t, "Authorize", {"idTag": tag})
            t += rng.uniform(1, 3)
        else:
            t += rng.uniform(2, 5)                              # ASSUMPTION: plug and charge without identification
        start, meter_start = t, self.meter
        first = 0 if p["session_energy"] else meter_start      # ABB, Grizzl-E count energy per session
        self.call(t, "StartTransaction", {"connectorId": 1, "idTag": tag, "meterStart": first,
                                          "timestamp": self.ts(t)}, queue=True, tx=tx)
        self.status(t + rng.uniform(*p["charging_delay"]), "Charging")
        if p["begin_meter"]:                                    # ABB: separate Transaction.Begin reading
            sv = {"value": "0", "context": "Transaction.Begin", "measurand": "Energy.Active.Import.Register", "unit": "Wh"}
            b = t + rng.uniform(3, 10)
            self.call(b, "MeterValues", {"connectorId": 1, "transactionId": tx,
                                         "meterValue": [{"timestamp": self.ts(b), "sampledValue": [sv]}]}, queue=True)
        if s["series"]:
            plan = MeasuredPlan(start, s["series"], s["kwh"])
        else:
            plan = ChargePlan(start, s["done"], s["disc"], s["kwh"])
        for x0, x1, status in plan.pauses:                      # real pauses during charging (measured curve)
            if x0 > 0:
                self.status(start + x0, status)
                self.status(start + x1, "Charging")
        if plan.d < s["disc"] - start - 60:
            self.status(start + plan.d, "SuspendedEV")          # car is full but still plugged in
        step = p["meter_interval"]
        for x in range(step, int(s["disc"] - start), step):
            mv = {"timestamp": self.ts(start + x), "sampledValue": self.samples(plan, x, first, step)}
            self.call(start + x, "MeterValues", {"connectorId": 1, "transactionId": tx, "meterValue": [mv]},
                      queue=True)
        self.meter = meter_start + round(s["kwh"] * 1000)
        self.sessions.append((start, s["disc"], tx, plan))
        t = s["disc"] + rng.random()
        stop = {"transactionId": tx, "idTag": tag, "meterStop": self.meter - meter_start + first,
                "timestamp": self.ts(t), "reason": "EVDisconnected"}
        if p["transaction_data"]:
            stop["transactionData"] = []                        # Wallbox always sends an empty list
        if p["finishing_before_stop"]:                          # ABB, Wallbox: Finishing first
            self.status(t - 0.3, "Finishing")
            self.call(t, "StopTransaction", stop, queue=True)
        else:
            self.call(t, "StopTransaction", stop, queue=True)
            self.status(t + 1, "Finishing")
        self.status(t + rng.uniform(*p["available_delay"]), "Available")
        self.label = "benign"

    def samples(self, plan, x, first, step):
        power = plan.power(x) * self.rng.gauss(1, 0.01)
        volt = plan.volt * self.rng.gauss(1, 0.005)          # measured: 204 V (JPL), 219 V (Caltech)
        values = {"Energy.Active.Import.Register": first + plan.energy(x),
                  "Energy.Active.Import.Interval": plan.energy(x) - plan.energy(x - step),
                  "Power.Active.Import": power, "Current.Import": power / volt, "Voltage": volt,
                  "Current.Offered": plan.offered(x), "Power.Offered": plan.offered(x) * plan.volt,
                  "Frequency": FREQUENCY + self.rng.gauss(0, 0.01)}
        rows = []
        for measurand, phase, unit, decimals in self.p["measurands"]:
            value = 0.0 if phase in ("L2", "L3") else values[measurand]  # single-phase charger: L2/L3 read 0
            row = {"value": f"{value:.{decimals}f}", "measurand": measurand, **self.p["sample_extra"]}
            if phase:
                row["phase"] = phase
            if unit:
                row["unit"] = unit
            rows.append(row)
        return rows

    def idle(self, a, b):
        """Rare events while nobody is charging (between a and b)."""
        for t in poisson_times(self.rng, a + 600, b - 600, REBOOT_PER_DAY):
            self.boot(t)
        for t in poisson_times(self.rng, a + 600, b - 600, FAULT_PER_DAY):
            back = t + self.rng.lognormvariate(math.log(300), 1)   # ASSUMPTION: fault clears after ~5 min
            if back < b:
                self.status(t, "Faulted", 1, self.rng.choice(FAULT_CODES))
                self.status(back, "Available")

    def clock_aligned(self, a, b, every):
        """Wallbox: lifetime energy on connectors 0 and 1 for every clock interval, stamped with the interval start."""
        for t in range(math.ceil(a / every) * every, int(b) - every, every):
            register, tx = self.meter0, None
            for start, end, session_tx, plan in self.sessions:
                if t >= start:
                    register += plan.energy(min(t, end) - start)
                    tx = session_tx if t < end else tx
            sv = {"context": "Sample.Clock", "format": "Raw", "location": "Outlet",
                  "measurand": "Energy.Active.Import.Register", "unit": "Wh", "value": f"{register:.1f}"}
            for connector in (0, 1):
                payload = {"meterValue": [{"timestamp": self.ts(t), "sampledValue": [sv]}], "connectorId": connector}
                if connector == 1 and tx:
                    payload["transactionId"] = tx
                self.call(t + every + 1, "MeterValues", payload)   # sent when the interval is over

    # ---- step 2: heartbeats ----------------------------------------------------------------------
    def heartbeats(self, a, b):
        """Send a Heartbeat whenever the charger was silent for one interval (as the real ABB does)."""
        times = sorted(c["t"] for c in self.calls if c["src"] == "cp") + [b]  # only own requests reset the timer
        last = a
        for nxt in times:
            while True:
                if self.p["hb_62"]:   # [FED] ABB: 85 % of gaps 60.0 s, 15 % 62.0 s
                    gap = HEARTBEAT - 0.001 if self.rng.random() > 0.15 else HEARTBEAT + 2
                else:                 # [CIC] Grizzl-E: 60.0 s, p1 59.6 / p99 60.4
                    gap = self.rng.gauss(HEARTBEAT, 0.17)
                if last + gap >= nxt - 1:     # a message due within 1 s already shows the charger is alive
                    break
                last += gap
                self.call(last, "Heartbeat", {})
            last = max(last, nxt)

    # ---- step 3: connection outages ------------------------------------------------------------
    def outages(self, a, b):
        self.calls.sort(key=lambda c: c["t"])
        for start in poisson_times(self.rng, a, b, OUTAGE_PER_DAY):
            end = start + self.rng.lognormvariate(math.log(180), 1)  # ASSUMPTION: ~3 min offline
            before = [c for c in self.calls if c["t"] < start and c["action"] == "StatusNotification"]
            kept = []
            for c in self.calls:
                if start <= c["t"] < end:
                    if not c["queue"]:
                        continue                  # heartbeats, status, authorize are lost
                    c["t"] = end + 1              # transaction messages wait for reconnect, order kept
                kept.append(c)
            self.calls = kept
            if before:                            # [FED] after reconnect: last status again, with its old timestamp
                self.call(end, "StatusNotification", dict(before[-1]["payload"]))
            self.calls.sort(key=lambda c: c["t"])

    # ---- step 4: on the wire -------------------------------------------------------------------
    def msg_ids(self):
        """Message IDs in the vendor's own style ([HA] logs)."""
        style = self.p["msg_ids"]
        fixed = random.Random(self.p["boot"]["firmwareVersion"])  # ABB: same 7-digit sequence after every boot
        while True:
            if style == "abb":
                yield f"{fixed.randrange(10**7):07d}"
            elif style == "grizzl":
                yield self.serial + f"{self.rng.getrandbits(32):08x}"
            else:
                yield str(self.rng.randrange(2**31))

    def frames(self):
        """Both directions as the backend sees them. The charger waits for each answer before the next call."""
        rng, ready, out, ids = self.rng, 0.0, [], self.msg_ids()
        for c in sorted(self.calls, key=lambda c: c["t"]):
            if c["src"] == "csms":                # backend call (SteVe uses UUIDs); the charger accepts it
                mid = str(uuid.UUID(int=rng.getrandbits(128), version=4))
                out.append((c["t"], "csms", [2, mid, c["action"], c["payload"]], c["label"]))
                out.append((c["t"] + NET_RTT + rng.uniform(0.1, 0.5), "cp", [3, mid, {"status": "Accepted"}],
                            c["label"]))  # ASSUMPTION: charger answers within 0.1-0.5 s
                continue
            if c["action"] == "BootNotification":
                ids = self.msg_ids()              # ID sequence restarts with every boot
            arrive = max(c["t"], ready) + NET_RTT / 2
            reply = arrive + rng.lognormvariate(math.log(SERVER_MEDIAN), SERVER_SIGMA)  # [FED] SteVe processing
            ready = reply + NET_RTT / 2
            mid = next(ids)
            out.append((arrive, "cp", [2, mid, c["action"], c["payload"]], c["label"]))
            out.append((reply, "csms", [3, mid, steve_response(c, reply)], c["label"]))
        return sorted(out, key=lambda f: f[0])


def steve_response(c, t):
    """What SteVe answers (CentralSystemService16_Service.java)."""
    a = c["action"]
    if a == "BootNotification":
        return {"status": "Accepted", "currentTime": iso(t), "interval": HEARTBEAT}
    if a == "Heartbeat":
        return {"currentTime": iso(t)}
    if a == "Authorize":
        return {"idTagInfo": {"status": c["auth"]}}
    if a == "StartTransaction":
        return {"idTagInfo": {"status": "Accepted"}, "transactionId": c["tx"]}
    if a == "StopTransaction":
        return {"idTagInfo": {"status": "Accepted"}}
    return {}


def load_measured(path):
    """Measured current per session (from fetcher.py --ts), keyed by (station, connectionTime)."""
    measured = {}
    if Path(path).exists():
        for line in open(path):
            r = json.loads(line)
            c, pilot = r["chargingCurrent"], r["pilotSignal"]
            if not (isinstance(c, dict) and c["current"]):
                continue                                          # early sessions have no series
            if not (isinstance(pilot, dict) and len(pilot["pilot"]) == len(c["current"])):
                pilot = {"pilot": [MAX_POWER / VOLTAGE] * len(c["current"])}  # some sessions lack the pilot: 32 A
            measured[(r["stationID"], epoch(r["connectionTime"]))] = {
                "t": [epoch(x) for x in c["timestamps"]], "i": c["current"], "p": pilot["pilot"]}
    return measured


def load_sessions(path, start, end, measured):
    by_station = {}
    for line in open(path):
        r = json.loads(line)
        s = {"conn": epoch(r["connectionTime"]), "done": epoch(r["doneChargingTime"]),
             "disc": epoch(r["disconnectTime"]), "kwh": r["kWhDelivered"], "user": r["userID"]}
        s["series"] = measured.get((r["stationID"], s["conn"]))
        if start <= s["conn"] and s["disc"] < end and s["disc"] > s["conn"]:
            by_station.setdefault(r["stationID"], []).append(s)
    for sessions in by_station.values():
        sessions.sort(key=lambda s: s["conn"])
    return by_station


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--site", default="jpl", choices=["caltech", "jpl", "office001"])
    ap.add_argument("--start", required=True, help="YYYY-MM-DD (UTC)")
    ap.add_argument("--end", required=True, help="YYYY-MM-DD (UTC), exclusive")
    ap.add_argument("--stations", type=int, default=0, help="limit number of chargers (0 = all)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    a = datetime.fromisoformat(args.start).replace(tzinfo=timezone.utc).timestamp()
    b = datetime.fromisoformat(args.end).replace(tzinfo=timezone.utc).timestamp()
    measured = load_measured(f"data/raw/acn_{args.site}_ts.jsonl")
    stations = load_sessions(f"data/raw/acn_{args.site}.jsonl", a, b, measured)
    names = sorted(stations)[: args.stations or None]

    args.out.mkdir(parents=True, exist_ok=True)
    for n, cp in build_all(stations, names, a, b, args.seed).items():
        write(args.out / f"{n}.jsonl", n, cp.frames())
        n_measured = sum(1 for s in stations[n] if s["series"])
        print(f"{n}: {cp.profile}, {len(cp.calls)} calls, {n_measured}/{len(stations[n])} sessions with measured current")


def build_all(stations, names, a, b, seed):
    """Simulate every charger (steps 1-3). Returns {chargerId: Charger}; call .frames() for step 4."""
    # SteVe numbers transactions in the order they start, across all chargers
    order = sorted((s["conn"], n, i) for n in names for i, s in enumerate(stations[n]))
    tx_ids = {(n, i): k + 1 for k, (_, n, i) in enumerate(order)}
    chargers = {}
    for n in names:
        rng = random.Random(f"{seed}-{n}")
        cp = chargers[n] = Charger(n, rng.choice(list(PROFILES)), rng)
        free_from = a
        for i, s in enumerate(stations[n]):
            if s["conn"] < free_from + 60:
                continue                                  # overlapping ACN record, skip
            cp.idle(free_from, s["conn"])
            cp.session(s, tx_ids[(n, i)])
            free_from = s["disc"] + 15
        cp.idle(free_from, b)
        if cp.p["clock_aligned"]:
            cp.clock_aligned(a, b, cp.p["clock_aligned"])
        cp.heartbeats(a, b)
        cp.outages(a, b)
    return chargers


def write(path, cp_id, frames):
    with open(path, "w") as f:
        for t, src, msg, label in frames:
            line = {"ts": iso(t, "us"), "src": src, "cp": cp_id, "label": label, "msg": msg}
            f.write(json.dumps(line, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
