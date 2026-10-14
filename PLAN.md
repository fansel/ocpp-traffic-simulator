# OCPP 1.6J Benign Traffic Generator – Plan

Goal: realistic **benign** OCPP 1.6J traffic (charge point ↔ CSMS) to train an anomaly-detection model
(benign-only training), later evaluated with injected anomalies: DoS, billing fraud, idTag misuse,
spoofing, message injection, protocol violations. The generator is a means to an end – keep it small.

## Decisions

| Topic | Decision | Why |
|---|---|---|
| Data level | **Decoded OCPP messages** (detector sits at the CSMS) | Fraud / injection / protocol violations are invisible in TLS flows; OCPP-specific IDS work (Dalamagkas et al. 2025) needs message features; CSMS decrypts anyway |
| TLS | Ablation only: one `wss` run with `SSLKEYLOGFILE` → encrypted flow view + decrypted view of the same traffic | "What do flow features miss?" is a contribution, not the main model |
| Behaviour source | ACN-Data (arrivals, dwell, kWh, recurring users) | Real; no public real benign multi-charger OCPP traffic exists |
| Fabricated parts | Vendor profiles, noise, rare benign events – parametrized + randomized | Domain randomization: detector learns "chargers differ" instead of simulator fingerprint |
| Backend | SteVe (Docker), real-time replay | Real responses, transactionIds, protocol validation; timing stays real |
| Realism check | Discriminator test (real vs synthetic, AUC≈0.5 goal) | Measurable instead of claimed |

## Pipeline

```
fetcher.py   ACN API → data/raw/acn_<site>.jsonl                       ✅ done
generator.py ACN sessions + profiles → timeline.jsonl (per CP)         ~200 LOC
replay.py    timeline → SteVe over ws/wss, one conn per CP, real time  ~100 LOC
             logs messages.jsonl (plaintext) + tcpdump → .pcap
attacks.py   anomalies for test sets only (same setup)                 later
realism.py   discriminator test vs real samples                        ~50 LOC
```

Mapping ACN → OCPP: `connectionTime` → Preparing → Authorize(idTag=hash(userID)) / RemoteStart →
StartTransaction → Charging + MeterValues → `doneChargingTime` → SuspendedEV → `disconnectTime` →
StopTransaction(EVDisconnected) → Finishing → Available. Idle: Heartbeat. Meter register monotonic per CP.

## Vendor profiles (sources: vendor manuals, lbbrhzn/ocpp issue logs, Federated dataset ABB capture)

Heartbeat interval is set by the CSMS in BootNotification.conf (seen 60–86400 s) → randomize per run.

| Profile | Based on | Key traits |
|---|---|---|
| P1 budget AC | Grizzl-E, Wallbox, Webasto | ws, MeterValues 30–60 s, Energy+Power+Current, messy fields (junk `meterType`, `location:"Body"`, short `vendorId`), brief Faulted on boot, connector-0 clock-aligned "0.0" |
| P2 premium AC | ABB Terra AC, Zaptec, Easee | wss, ws ping 10–60 s, 4–6 measurands incl. per-phase/Current.Offered/Voltage, clean frames, `vendorErrorCode "0x0000"` |
| P3 public multi-connector AC | Mennekes, KEBA, Etrel | 2–6 connectors, clock-aligned MeterValues (300–3600 s) even when idle, `transactionData` in StopTransaction, optionally kWh/kW units |
| P4 DC fast | Alpitronic, ABB Terra 54 | SoC, vendor DataTransfer after start, numeric vendor error codes; sample interval 30 s (ABB capture) |

Measured on a real ABB Terra 54 + SteVe (Federated dataset): heartbeat 60 s only when idle, CP ws ping 30 s,
SteVe ping 900 s, reconnect + BootNotification ~every 4 h, boot burst incl. Faulted/OtherError on connectors 0–3,
message IDs `"<bootCounter>:<seq>"`, latency p50 ≈ 45 ms / p95 ≈ 100 ms (Wi-Fi), no TLS, no permessage-deflate.

## Rare benign events (rates from ACN zero-kWh sessions / data gaps + EV WATTS reliability report)
Connector fault + recovery · connection loss + offline queue burst · site-wide power loss (correlated reboot storm) ·
rejected idTag · aborted session (EVCommunicationError) · missing/duplicate MeterValues · nightly firmware update.

## Volume & splits
- ~600 msgs/CP/day → 100 CPs ≈ 120k msgs/day; 30–60 selected ACN days (weekday/weekend/holiday/outage, all sites)
  ≈ 4–7M messages; 5–10 parallel SteVe stacks ≈ 1 week wall-clock. Re-seed days for extra variation.
- Learning curve (10/25/50/100 %) decides whether more is needed.
- Split by ACN day (never random); hold out one site; benign stress test (holidays/outages); anomalies 1–5 % in test only.

## Reference data
- **Federated OCPP 1.6 IDS dataset** (Zenodo 14887131, CC-BY): only decodable real-hardware capture (ABB Terra 54 + SteVe); attack runs through whole capture → use CP-originated non-attack messages for calibration/discriminator.
- **lbbrhzn/ocpp issues**: ~6k real frames, ~50 vendor/model combos → payload structure & measurands.
- **CICEVSE2024**: Grizzl-E over TLS (heartbeat 60 s, ws ping ~6 s); network attacks only; little benign.
- **Coventry hybrid testbed** (= our `benign_*.csv`): scripted, unrealistic timing; feature schema only.

## Open: real benign data
Own cheap wallbox → SteVe (best ground truth) · ask Federated/Coventry authors for benign baselines ·
companies contacted · AAU faculties.

## OCPP 1.6J reference (what the generator must reproduce)

Sources: official JSON schemas (bundled in `ocpp` lib, `ocpp/v16/schemas`), SteVe source
(`CentralSystemService16_Service.java`), real ABB capture (Federated dataset).

**Transport.** WebSocket `ws(s)://<csms>/steve/websocket/CentralSystemService/<chargeBoxId>`, subprotocol `ocpp1.6`.
One outstanding CALL per direction (wait for the answer before the next). ws ping from CP (ABB 30 s), SteVe 900 s.

**Framing (OCPP-J).**
```
CALL        [2, "<msgId ≤36>", "<Action>", {payload}]
CALLRESULT  [3, "<msgId>", {payload}]
CALLERROR   [4, "<msgId>", "<ErrorCode>", "<description>", {details}]
ErrorCode ∈ NotImplemented|NotSupported|InternalError|ProtocolError|SecurityError|FormationViolation|
            PropertyConstraintViolation|OccurenceConstraintViolation|TypeConstraintViolation|GenericError
```

**Charger → CSMS (what benign traffic consists of)**

| Action | Payload (required*) | SteVe response |
|---|---|---|
| BootNotification | chargePointVendor*≤20, chargePointModel*≤20, serials ≤25, firmwareVersion ≤50, iccid/imsi ≤20, meterType/Serial ≤25 | `{status: Accepted\|Rejected(unknown CP), currentTime, interval: <setting>}` |
| Heartbeat | `{}` | `{currentTime}` (format `2023-04-26T11:02:08.123Z`) |
| StatusNotification | connectorId*, errorCode* (16 values), status* (Available, Preparing, Charging, SuspendedEVSE, SuspendedEV, Finishing, Reserved, Unavailable, Faulted), timestamp, info ≤50, vendorId, vendorErrorCode ≤50 | `{}` |
| Authorize | idTag* ≤20 | `{idTagInfo:{status: Accepted\|Blocked\|Expired\|Invalid, expiryDate?, parentIdTag?}}`; unknown tag → Invalid |
| StartTransaction | connectorId*, idTag*, meterStart* (int Wh), timestamp*, reservationId | `{idTagInfo, transactionId: DB auto-increment}` |
| MeterValues | connectorId*, transactionId, meterValue*[{timestamp*, sampledValue*[{value* (string), context, format, measurand (22), phase, location, unit}]}] | `{}` |
| StopTransaction | transactionId*, meterStop* (int Wh), timestamp*, idTag, reason (11 values), transactionData[] | `{idTagInfo}` (if idTag sent) |
| DataTransfer | vendorId*, messageId, data | `{status: Accepted}` (SteVe dummy) |
| Firmware/DiagnosticsStatusNotification | status* | `{}` |

**CSMS → charger (sparse in benign traffic):** RemoteStart/StopTransaction (app starts), TriggerMessage,
Get/ChangeConfiguration (after boot), SetChargingProfile (ACN is a smart-charging network), Reset, ChangeAvailability,
UnlockConnector — each with simple `{status}` answers.

**Behavioural rules to respect.** Status transitions per spec state table · MeterValues in a tx carry `transactionId`,
contexts Transaction.Begin / Sample.Periodic / Sample.Clock / Transaction.End · `meterStart/meterStop` integer Wh and
register monotonic · transaction messages queued while offline and resent in order on reconnect · values are strings ·
heartbeat may be skipped while other traffic flows (ABB does) · Boot on every (re)connect for some vendors.

## Code budget

| File | LOC | Content |
|---|---|---|
| `profiles.py` | ~80 (data) | 4 vendor profiles: boot strings, msgId style, intervals, measurands, units, quirks, network latency params |
| `generator.py` | ~300 | ACN load + station→CP/profile (30) · power curve & meter (30) · per-CP event loop on virtual clock, heapq (60) · session flow (50) · idle traffic: heartbeat, ping, clock-aligned MV, reconnect+boot burst (40) · rare events (40) · SteVe-exact responses + latency (25) · schema validation + JSONL writer (25) |
| `live.py` | ~80 | same per-CP event stream sent to real SteVe via `ocpp` lib; logs real responses/latency for validation |
| `realism.py` | ~60 | stats comparison + discriminator (real ABB/lbbrhzn vs synthetic) |
| `docker-compose.yml` | ~20 | SteVe + MySQL (upstream compose) |
| **Total** | **≈ 450 Python + 80 data** | |

Deliberately skipped (add only if needed): Reservations, LocalAuthList, certificates/security extensions,
GetDiagnostics/firmware download flows beyond status notifications, multi-CSMS.
