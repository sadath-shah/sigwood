#!/usr/bin/env python3
# flatten_own.py - one CloudTrail file → parquet (same projection as flaws)
import json, sys, os
import pandas as pd

SRC = sys.argv[1] if len(sys.argv) > 1 else "cloudtrail_20260520_to_20260603_00h.json.log"
OUT = os.path.splitext(SRC)[0] + ".parquet"

READ_PREFIXES = ("Get","List","Describe","Head","Lookup","Search","BatchGet","Select","Query","Scan")

def principal(ui):
    p = ui.get("principalId","") or ""
    return p.split(":")[-1] if ":" in p else (p or ui.get("type","?"))

def flatten(e):
    ui = e.get("userIdentity",{}) or {}
    attrs = (ui.get("sessionContext",{}) or {}).get("attributes",{}) or {}
    name = e.get("eventName") or ""
    return {
        "eventTime": e.get("eventTime"),
        "eventSource": (e.get("eventSource") or "").replace(".amazonaws.com",""),
        "eventName": name,
        "eventType": e.get("eventType"),
        "awsRegion": e.get("awsRegion"),
        "sourceIP": e.get("sourceIPAddress"),
        "userAgent": e.get("userAgent"),
        "id_type": ui.get("type"),
        "principal": principal(ui),
        "arn": ui.get("arn"),
        "accountId": ui.get("accountId") or e.get("recipientAccountId"),
        "invokedBy": ui.get("invokedBy"),
        "mfa": attrs.get("mfaAuthenticated") == "true",
        "accessKeyId": ui.get("accessKeyId"),
        "readOnly_raw": e.get("readOnly"),
        "is_read": name.startswith(READ_PREFIXES),
        "errorCode": e.get("errorCode"),
        "errorMessage": e.get("errorMessage"),
        "has_request": bool(e.get("requestParameters")),
        "has_response": bool(e.get("responseElements")),
        "has_resources": bool(e.get("resources")),
        "eventVersion": e.get("eventVersion"),
        "eventID": e.get("eventID"),
    }

# tolerate either {"Records":[...]} OR one-JSON-per-line (your sample was JSONL)
with open(SRC) as f:
    text = f.read().strip()
try:
    obj = json.loads(text)
    recs = obj["Records"] if isinstance(obj, dict) and "Records" in obj else (obj if isinstance(obj, list) else [obj])
except json.JSONDecodeError:
    recs = [json.loads(ln) for ln in text.splitlines() if ln.strip()]

df = pd.DataFrame(flatten(e) for e in recs)
df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce", utc=True)
df = df.sort_values("eventTime").reset_index(drop=True)
df.to_parquet(OUT, engine="pyarrow", compression="zstd", index=False)
print(f"{len(df):,} events → {OUT}  ({os.path.getsize(OUT)/1e6:.1f} MB)")
print(f"span: {df['eventTime'].min()} → {df['eventTime'].max()}")
