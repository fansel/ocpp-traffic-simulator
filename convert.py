import json
import os
import sys
import uuid
from datetime import datetime, timedelta

def acn_to_datetime(acn_date_str):
    if not acn_date_str:
        return None
    return datetime.strptime(acn_date_str, "%a, %d %b %Y %H:%M:%S GMT")

def to_ocpp_iso(dt):
    if not dt:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def generate_real_ocpp_messages(acn_line, index):
    data = json.loads(acn_line)
    wh_delivered = int(float(data["kWhDelivered"]) * 1000)
    tx_id = 1000 + index
    station_id = data["stationID"]

    start_dt = acn_to_datetime(data["connectionTime"])
    end_dt = acn_to_datetime(data["disconnectTime"])
    done_dt = acn_to_datetime(data["doneChargingTime"]) or end_dt

    # KORREKTUR: Wenn MeterValues zeitlich NACH oder GLEICH dem Stop liegt,
    # setzen wir es auf genau 1 Sekunde VOR dem Stop, damit die OCPP-Reihenfolge stimmt.
    if done_dt >= end_dt:
        done_dt = end_dt - timedelta(seconds=1)

    start_msg = [
        2, f"msg_{uuid.uuid4().hex[:8]}", "StartTransaction",
        {
            "connectorId": 1,
            "idTag": "ACN_ANONYMOUS" if data["userID"] is None else str(data["userID"]),
            "meterStart": 0,
            "timestamp": to_ocpp_iso(start_dt)
        }
    ]

    meter_msg = [
        2, f"msg_{uuid.uuid4().hex[:8]}", "MeterValues",
        {
            "connectorId": 1,
            "transactionId": tx_id,
            "meterValue": [{
                "timestamp": to_ocpp_iso(done_dt),
                "sampledValue": [{
                    "value": str(wh_delivered),
                    "context": "Sample.Periodic",
                    "measurand": "Energy.Active.Import.Register",
                    "unit": "Wh"
                }]
            }]
        }
    ]

    stop_msg = [
        2, f"msg_{uuid.uuid4().hex[:8]}", "StopTransaction",
        {
            "transactionId": tx_id,
            "timestamp": to_ocpp_iso(end_dt),
            "meterStop": wh_delivered,
            "reason": "EVDisconnected"
        }
    ]

    # Wir fügen eine 'priority' (0=Start, 1=Meter, 2=Stop) für den Sortierungs-Key hinzu
    return [
        {"timestamp_dt": start_dt, "priority": 0, "ocpp_raw": start_msg},
        {"timestamp_dt": done_dt, "priority": 1, "ocpp_raw": meter_msg},
        {"timestamp_dt": end_dt, "priority": 2, "ocpp_raw": stop_msg}
    ]

def main():
    if len(sys.argv) < 2:
        print("Usage: python convert.py <filename.jsonl>")
        sys.exit(1)

    # Korrektur hier: [1] holt den String aus der Argumentenliste
    input_file = sys.argv[1]

    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        sys.exit(1)

    name_part, ext_part = os.path.splitext(input_file)
    output_file = f"{name_part}_real_ocpp{ext_part}"

    all_single_messages = []

    with open(input_file, "r", encoding="utf-8") as infile:
        for idx, line in enumerate(infile):
            if not line.strip():
                continue
            all_single_messages.extend(generate_real_ocpp_messages(line, idx))

    # Sortiert primär nach Zeitstempel, sekundär nach Priorität (Start -> Meter -> Stop)
    all_single_messages.sort(key=lambda x: (x["timestamp_dt"], x["priority"]))

    with open(output_file, "w", encoding="utf-8") as outfile:
        for item in all_single_messages:
            outfile.write(json.dumps(item["ocpp_raw"]) + "\n")

    print(f"Converted and Chronologically Sorted: {output_file}")

if __name__ == "__main__":
    main()
