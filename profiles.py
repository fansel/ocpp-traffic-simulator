"""Vendor profiles: how a specific charger model talks OCPP 1.6J.

Every value is copied from a real source (see comments) or marked ASSUMPTION.
Sources:
  [ABB]  ABB Terra AC OCPP 1.6 Implementation Overview v1.8
  [HA#n] real charger logs in github.com/lbbrhzn/ocpp issue n (Home Assistant OCPP integration)
  [FED]  real ABB Terra 54 + SteVe capture, Federated OCPP 1.6 dataset (Zenodo 14887131)
  [CIC]  real Grizzl-E capture, CICEVSE2024 (TLS: only sizes and timing)

Measurand rows: (measurand, phase, unit, decimals); unit None = field left out (Wallbox Frequency).
"""

PROFILES = {
    "abb_terra_ac": {
        "boot": {  # [HA#1275] verbatim apart from the serial number
            "chargePointVendor": "ABB",
            "chargePointModel": "CDT_TACW22::NET_WIFI",
            "chargePointSerialNumber": "TACW22{serial}",
            "chargeBoxSerialNumber": "TACW22{serial}",
            "firmwareVersion": "TAC3Z9119006710273::V1.8.21",
            "meterType": "V1",
        },
        "serial_digits": True,
        "msg_ids": "abb",                 # [HA#1275,#1717] 7-digit fixed sequence, restarts after every boot
        "start": "rfid",                  # Terra AC has an RFID reader; ACN sessions with a user tap a card
        "status_extra": {"info": "null", "vendorErrorCode": "0x0000"},  # [HA#1275]
        "status_info": {},
        "status_has_timestamp": False,    # [HA#1275] firmware 1.8.21
        "boot_connectors": [0, 1],        # [HA#880]
        "ts_style": "s000",               # [HA] timestamps always end in ".000Z"
        "meter_interval": 60,             # [HA#1717,#1741,#1767]
        "session_energy": True,           # [HA#1767] meterStart 0, energy counts per session
        "measurands": [("Voltage", "L1-N", "V", 2), ("Current.Import", "L1", "A", 2),
                       ("Power.Active.Import", "L1", "W", 0), ("Energy.Active.Import.Register", None, "Wh", 0),
                       ("Current.Offered", None, "A", 0)],  # [HA#1767]
        "sample_extra": {},
        "begin_meter": True,              # [HA#906,#1741] separate Transaction.Begin reading (energy 0) 3-10 s after Start
        "charging_delay": (-0.8, -0.8),   # [HA#169,#906] Charging is sent 0.8 s BEFORE StartTransaction
        "finishing_before_stop": True,    # [HA#169,#906]
        "available_delay": (1, 3),        # ASSUMPTION: Available right after the cable is pulled
        "transaction_data": False,
        "hb_62": True,                    # [FED] 85 % 60.0 s / 15 % 62.0 s (ABB Terra 54)
        "boot_fault": 0.0,
        "clock_aligned": None,
    },
    "grizzl_e": {
        "boot": {  # [HA#176,#442] firmware 05.6xx, verbatim apart from serial and signal strength
            "chargePointSerialNumber": "GRS-{serial}",
            "chargePointModel": "GRS-*",
            "chargePointVendor": "United Chargers",
            "firmwareVersion": "05.633:A3A5:2A3C",
            "meterType": "SW",
            "iccid": "-{rssi}",               # [HA] values -9 ... -83, looks like signal strength
            "imsi": "1",
        },
        "serial_digits": False,
        "msg_ids": "grizzl",              # [HA#176] serial + 8 hex digits
        "start": "freevend",              # [HA#176] authorizes itself 1-2 s after plug-in with its own serial
        "status_extra": {"vendorId": "UC", "vendorErrorCode": "0"},  # [HA#442]
        "status_info": {"Available": "Pilot and Charger:A1h", "Charging": "Prep->Charging"},  # [HA#442,#176]
        "status_has_timestamp": True,
        "boot_connectors": [1],           # [HA] firmware 05.x reports connector 1 only
        "ts_style": "s001",               # [HA#176,#442] timestamps always end in ".001Z"
        "meter_interval": 60,             # [HA#442]
        "session_energy": True,           # [HA#176] meterStart 0
        "measurands": [("Current.Import", "L1-N", "A", 2), ("Power.Active.Import", "L1-N", "W", 2),
                       ("Energy.Active.Import.Register", "L1-N", "Wh", 2)],  # [HA#176]
        "sample_extra": {"context": "Sample.Periodic", "format": "Raw", "location": "Body"},  # [HA#176]
        "begin_meter": False,
        "charging_delay": (6, 7),         # [HA#176]
        "finishing_before_stop": False,
        "available_delay": (2, 10),       # ASSUMPTION
        "transaction_data": False,
        "hb_62": False,                   # [CIC] 60.0 s +-0.4 s, no 62 s mode
        "boot_fault": 0.0,
        "clock_aligned": None,
    },
    "wallbox_pulsar": {
        "boot": {  # [HA#1756] verbatim apart from the serial number
            "chargePointSerialNumber": "{serial}",
            "chargePointVendor": "Wall Box Chargers",
            "meterType": "Internal NON compliant",
            "meterSerialNumber": "",
            "chargePointModel": "PUP1-U-1-6",
            "iccid": "",
            "chargeBoxSerialNumber": "{serial}",
            "firmwareVersion": "6.8.12",
            "imsi": "",
        },
        "serial_digits": True,
        "msg_ids": "int",                 # [HA#1725,#1742] random decimal up to 2^31
        "start": "app",                   # Pulsar Plus has no card reader: users start via app = RemoteStartTransaction
        "status_extra": {"info": "", "vendorId": "com.wallbox", "vendorErrorCode": ""},  # [HA#1756]
        "status_info": {},
        "status_has_timestamp": True,
        "boot_connectors": [0, 1],        # [HA#1756]
        "ts_style": "s",                  # [HA#1756] "2025-12-06T16:57:45Z"
        "meter_interval": 60,             # [HA#1245]
        "session_energy": False,          # [HA#1742] lifetime register
        "measurands": [("Current.Import", "L1", "A", 1), ("Current.Import", "L2", "A", 1),
                       ("Current.Import", "L3", "A", 1), ("Energy.Active.Import.Register", None, "Wh", 1),
                       ("Energy.Active.Import.Interval", None, "Wh", 1), ("Power.Active.Import", None, "W", 1),
                       ("Power.Offered", None, "W", 0), ("Frequency", None, None, 1)],  # [HA#1742]
        "sample_extra": {"context": "Sample.Periodic", "location": "Outlet"},  # [HA#1742]
        "begin_meter": False,
        "charging_delay": (4.4, 7.4),     # [HA#1725,#1742,#1877]
        "finishing_before_stop": True,    # [HA#1742] Finishing 0.3 s before StopTransaction
        "available_delay": (20, 50),      # [HA#1742,#1069]
        "transaction_data": True,         # [HA#1742] always "transactionData": []
        "hb_62": False,                   # ASSUMPTION (no Wallbox timing capture)
        "boot_fault": 1 / 3,              # [HA#1756 vs #1207,#1684] Faulted on boot on some boots
        "clock_aligned": 900,             # [HA#1756] connectors 0 and 1; 900 s is set by the backend
    },
}


# [FED] split of the measured response time: network round trip ~1 ms (LAN), SteVe processing
# log-normal with median 40 ms and p95 100 ms (sigma 0.56).
NET_RTT, SERVER_MEDIAN, SERVER_SIGMA = 0.001, 0.040, 0.56
