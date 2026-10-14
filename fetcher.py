"""Download ACN-Data charging sessions (https://ev.caltech.edu/dataset) to local JSONL files.

Usage:
    export ACN_TOKEN=...            # or pass --token
    python fetcher.py                               # all sites, all time
    python fetcher.py --sites jpl --start 2019-01-01 --end 2019-04-01
    python fetcher.py --sites jpl --start 2019-03-01 --end 2019-04-01 --ts   # + measured current per session

Writes one session per line to data/raw/acn_<site>.jsonl (with --ts: acn_<site>_ts.jsonl, stored as returned). Re-running resumes after the
newest connectionTime already on disk, so an interrupted download can simply be restarted.
"""
import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

API = "https://ev.caltech.edu/api/v1/"
SITES = ("caltech", "jpl", "office001")
PAGE_SIZE = 25


def rfc1123(dt: datetime) -> str:
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")


def get_json(url: str, token: str, retries: int = 5) -> dict:
    auth = base64.b64encode(f"{token}:".encode()).decode()
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}"})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                sys.exit(f"Auth failed ({e.code}) - check your ACN token.")
            if attempt == retries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
        time.sleep(2 ** attempt)


def last_connection_time(path: Path) -> datetime | None:
    if not path.exists():
        return None
    latest = None
    with path.open() as f:
        for line in f:
            t = parsedate_to_datetime(json.loads(line)["connectionTime"])
            latest = t if latest is None or t > latest else latest
    return latest


def fetch_site(site: str, token: str, out: Path, start: datetime | None, end: datetime | None, ts: bool) -> int:
    path = out / f"acn_{site}{'_ts' if ts else ''}.jsonl"
    resume = last_connection_time(path)
    conds = []
    if resume:
        conds.append(f'connectionTime>"{rfc1123(resume)}"')
        print(f"[{site}] resuming after {resume:%Y-%m-%d %H:%M}")
    elif start:
        conds.append(f'connectionTime>="{rfc1123(start)}"')
    if end:
        conds.append(f'connectionTime<"{rfc1123(end)}"')

    # docs say time series are limited to 1 per page, but tested 2026-10-09: 25 complete series per page work
    params = {"sort": "connectionTime", "max_results": PAGE_SIZE}
    if conds:
        params["where"] = " and ".join(conds)
    url = f"{API}sessions/{site}{'/ts' if ts else ''}?{urllib.parse.urlencode(params)}"

    n = 0
    with path.open("a") as f:
        while url:
            page = get_json(url, token)
            for s in page["_items"]:
                f.write(json.dumps(s) + "\n")
            f.flush()
            n += len(page["_items"])
            total = page.get("_meta", {}).get("total", "?")
            print(f"[{site}] {n}/{total} sessions", end="\r", flush=True)
            nxt = page.get("_links", {}).get("next")
            # the API returns the next-page link unencoded (spaces in the date filter)
            url = API + urllib.parse.quote(nxt["href"], safe="/?&=%") if nxt else None
    print(f"[{site}] done: {n} new sessions -> {path}")
    return n


def parse_date(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--token", default=os.environ.get("ACN_TOKEN"), help="ACN API token (default: $ACN_TOKEN)")
    p.add_argument("--sites", nargs="+", choices=SITES, default=list(SITES))
    p.add_argument("--start", type=parse_date, help="YYYY-MM-DD, inclusive (UTC)")
    p.add_argument("--end", type=parse_date, help="YYYY-MM-DD, exclusive (UTC)")
    p.add_argument("--out", type=Path, default=Path("data/raw"))
    p.add_argument("--ts", action="store_true", help="fetch measured charging current per session")
    a = p.parse_args()
    if not a.token and Path(".env").exists():  # fallback: a line ACN_TOKEN=... in .env (git-ignored)
        a.token = dict(l.strip().split("=", 1) for l in open(".env") if "=" in l).get("ACN_TOKEN")
    if not a.token:
        sys.exit("No token: set ACN_TOKEN, pass --token, or put ACN_TOKEN=... in .env")
    a.out.mkdir(parents=True, exist_ok=True)
    for site in a.sites:
        fetch_site(site, a.token, a.out, a.start, a.end, a.ts)


if __name__ == "__main__":
    main()
