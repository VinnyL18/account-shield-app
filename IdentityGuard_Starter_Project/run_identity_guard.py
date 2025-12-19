"""
run_identity_guard.py – main script to run IdentityGuard scan.
"""

import json
from pathlib import Path

from db import init_db, save_events
from email_fetcher import EmailFetcher
from parser import parse_security_email


def load_config(path: str = "config.json") -> dict:
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise SystemExit(
            f"Config file {path} not found. "
            "Copy config.example.json to config.json and edit your settings."
        )
    with cfg_path.open() as f:
        return json.load(f)


def main():
    config = load_config()
    init_db()

    fetcher = EmailFetcher(
        host=config["imap_host"],
        port=config["imap_port"],
        username=config["username"],
        password=config["password"],
        provider=config.get("provider", "gmail"),
    )

    events = []
    with fetcher:
        messages = fetcher.fetch_security_messages(
            max_messages=config.get("max_messages", 50)
        )
        print(f"Fetched {len(messages)} raw messages")

        for uid, msg in messages:
            event = parse_security_email(config.get("provider", "gmail"), uid, msg)
            events.append(event)

    inserted = save_events(events)
    print(f"Inserted {inserted} new events into identityguard.db")

    # Quick terminal summary by risk level
    highs = [e for e in events if e["risk_level"] == "high"]
    meds = [e for e in events if e["risk_level"] == "medium"]
    lows = [e for e in events if e["risk_level"] == "low"]

    print("\nSummary of this scan:")
    print(f"  High risk events:   {len(highs)}")
    print(f"  Medium risk events: {len(meds)}")
    print(f"  Low risk events:    {len(lows)}")

    if highs:
        print("\nHigh risk details:")
        for e in highs:
            print(f"- [{e['service']}] {e['event_type']} at {e['time_utc']} IP={e['ip']} loc={e['location']}")


if __name__ == "__main__":
    main()
