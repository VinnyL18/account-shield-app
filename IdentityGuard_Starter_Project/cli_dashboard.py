"""
cli_dashboard.py – simple terminal dashboard for IdentityGuard.

This lets you explore the events stored in identityguard.db:
- View a risk summary
- See recent events
- See recent HIGH risk events
- Inspect one event in detail
"""

import sqlite3
from pathlib import Path
from textwrap import shorten

from url_guard import analyze_urls_for_recent_events

DB_PATH = Path("identityguard.db")


def get_conn():
    if not DB_PATH.exists():
        print("⚠ identityguard.db not found. Run run_identity_guard.py first.")
        return None
    return sqlite3.connect(DB_PATH)


def show_summary(conn):
    cur = conn.cursor()
    cur.execute(
        "SELECT risk_level, COUNT(*) FROM events GROUP BY risk_level ORDER BY risk_level DESC"
    )
    rows = cur.fetchall()
    total = sum(count for _, count in rows)

    print("\n=== Risk Summary ===")
    print(f"Total events: {total}")
    for level, count in rows:
        print(f"  {level.upper():6}: {count}")
    print()


def show_recent(conn, limit=10, only_high=False):
    cur = conn.cursor()
    
    if only_high:
        cur.execute(
            """
            SELECT id, provider, service, event_type, time_utc, risk_level, raw_subject, raw_snippet
            FROM events
            WHERE risk_level = 'high'
            ORDER BY time_utc DESC
            LIMIT ?
            """,
            (limit,),
        )
        title = f"Last {limit} HIGH risk events"
    else:
        cur.execute(
            """
            SELECT id, provider, service, event_type, time_utc, risk_level, raw_subject, raw_snippet
            FROM events
            ORDER BY time_utc DESC
            LIMIT ?
            """,
            (limit,),
        )
        title = f"Last {limit} events"

    rows = cur.fetchall()
    print(f"\n=== {title} ===")
    if not rows:
                    print("No events found.\n")
                    return
                
    print(f"{'ID':>4} {'RISK':6} {'SERVICE':15} {'EVENT TYPE':20} {'TIME (UTC)':20} SUBJECT")
    print("-" * 90)
                
    for (
                    ev_id,
                    provider,
                    service,
                    event_type,
                    time_utc,
                    risk_level,
                    raw_subject,
                    raw_snippet,
                ) in rows:
                    subject = raw_subject or raw_snippet or "(no subject)"
                    subj_short = shorten(subject, width=40, placeholder="-")
                
                    print(
                        f"{ev_id:>4} {risk_level.upper():6} {service[:15]:15} "
                        f"{event_type[:20]:20} {time_utc[:19]:20} {subj_short}"
                    )
                
    print()
def show_password_changes(conn, limit=10):
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, provider, service, event_type, time_utc, risk_level, raw_subject
        FROM events
        WHERE event_type = 'password_change'
        ORDER BY time_utc DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()

    print(f"\n=== Last {limit} PASSWORD CHANGE events ===")
    if not rows:
        print("No password change events found.\n")
        return

    print(f"{'ID':>4} {'RISK':<6} {'SERVICE':15} {'TIME (UTC)':20} SUBJECT")
    print("-" * 90)
    for ev_id, provider, service, event_type, time_utc, risk_level, subject in rows:
        # Re-use the shorten() helper already imported at the top of this file
        subj_short = shorten(subject or "(no subject)", width=50, placeholder="…")
        print(
            f"{ev_id:>4} "
            f"{risk_level.upper():<6} "
            f"{(service or '')[:15]:15} "
            f"{(time_utc or '')[:19]:20} "
            f"{subj_short}"
        )
    print()
   
def show_event_detail(conn, event_id: int):
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, provider, service, event_type, account_email,
               ip, location, device, time_utc, risk_level,
               raw_subject, raw_snippet
        FROM events
        WHERE id = ?
        """,
        (event_id,),
    )
    row = cur.fetchone()
    if not row:
        print(f"\nNo event found with id {event_id}\n")
        return

    (
        ev_id,
        provider,
        service,
        event_type,
        account_email,
        ip,
        location,
        device,
        time_utc,
        risk_level,
        raw_subject,
        raw_snippet,
    ) = row

    print("\n=== Event Detail ===")
    print(f"ID:           {ev_id}")
    print(f"Provider:     {provider}")
    print(f"Service:      {service}")
    print(f"Event type:   {event_type}")
    print(f"Risk level:   {risk_level.upper()}")
    print(f"Time (UTC):   {time_utc}")
    print(f"Account:      {account_email}")
    print(f"IP:           {ip}")
    print(f"Location:     {location}")
    print(f"Device:       {device}")
    print(f"Subject:      {raw_subject}")
    print("\nBody snippet:\n")
    print(raw_snippet)
    print("\n====================\n")

def analyze_identity_changes(conn, limit: int = 100):
    """
    Look at the last `limit` events and flag
    new IPs, locations, or devices we haven't seen before
    for each (service, account_email) pair.
    """
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, service, account_email, time_utc,
               ip, location, device, risk_level, event_type
        FROM events
        ORDER BY time_utc ASC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()

    print(f"\n=== Identity Change Analysis (last {limit} events) ===")

    if not rows:
        print("No events found.\n")
        return

    # Track what we've already seen per (service, account)
    seen = {}  # (service, account_email) -> {"ips": set(), "locs": set(), "devs": set()}
    anomalies = []  # list of (id, service, account, time, ip, loc, dev, tags)

    for (
        ev_id,
        service,
        account_email,
        time_utc,
        ip,
        location,
        device,
        risk_level,
        event_type,
    ) in rows:
        key = (service or "Unknown", account_email or "Unknown")
        state = seen.setdefault(key, {"ips": set(), "locs": set(), "devs": set()})

        tags = []

        # New IP for this service/account?
        if ip:
            if state["ips"] and ip not in state["ips"]:
                tags.append("NEW_IP")
            state["ips"].add(ip)

        # New location?
        if location:
            if state["locs"] and location not in state["locs"]:
                tags.append("NEW_LOCATION")
            state["locs"].add(location)

        # New device?
        if device:
            if state["devs"] and device not in state["devs"]:
                tags.append("NEW_DEVICE")
            state["devs"].add(device)

        if tags:
            anomalies.append(
                (ev_id, service, account_email, time_utc, ip, location, device, tags)
            )

    if not anomalies:
        print("No new IPs/locations/devices detected in this window.\n")
        return

    print(
        f"{'ID':>4}  {'SERVICE':15}  {'ACCOUNT':25}  {'TIME (UTC)':19}  "
        f"{'IP':15}  {'LOCATION':20}  {'DEVICE':15}  FLAGS"
    )
    print("-" * 120)
    for ev_id, service, account_email, time_utc, ip, location, device, tags in anomalies:
        print(
            f"{ev_id:>4}  { (service or '')[:15]:15}  {(account_email or '')[:25]:25}  "
            f"{(time_utc or '')[:19]:19}  {(ip or '')[:15]:15}  {(location or '')[:20]:20}  "
            f"{(device or '')[:15]:15}  {', '.join(tags)}"
        )
def show_alerts(conn, limit=20):
    cur = conn.cursor()
    cur.execute(
        """
        SELECT alerts.id, events.event_type, events.time_utc, events.service,
               events.account_email, alerts.delivered
        FROM alerts
        JOIN events ON alerts.event_id = events.id
        ORDER BY alerts.id DESC
        LIMIT ?
        """,
        (limit,)
    )
    rows = cur.fetchall()

    print(f"\n=== Last {limit} CRITICAL ALERTS ===")
    if not rows:
        print("No alerts found.\n")
        return

    print(f"{'ID':>4} {'EVENT':15} {'TIME UTC':20} {'SERVICE':15} {'ACCOUNT':25} {'DELIVERED':10}")
    print("-" * 100)

    for alert_id, event_type, time_utc, service, account_email, delivered in rows:
        delivered_status = "YES" if delivered == 1 else "NO"
        print(
            f"{alert_id:>4} {event_type:15} {time_utc:20} {service:15} "
            f"{(account_email or ''):25} {delivered_status:10}"
        )

    print()

def main():
    conn = get_conn()
    if conn is None:
        return

    while True:
        print("=== IdentityGuard CLI Dashboard ===")
        print("1) Show risk summary")
        print("2) Show last 10 events")
        print("3) Show last 10 HIGH risk events")
        print("4) Show details for a specific event ID")
        print("5) Quit")
        print("6) Scan URLs in the last 20 events")
        print("7) Analyze new IPs/locations/devices (last 100 HIGH/MED events)")
        print("8) Show last 10 PASSWORD CHANGE events")
        print("9) Show last 20 CRITICAL ALERTS")
        choice = input("\nSelect an option (1-9): ").strip()

        if choice == "1":
            show_summary(conn)
        elif choice == "2":
            show_recent(conn, limit=10, only_high=False)
        elif choice == "3":
            show_recent(conn, limit=10, only_high=True)
        elif choice == "4":
            ...
        elif choice == "5":
            print("\nExiting dashboard.\n")
            break
        elif choice == "6":
            analyze_urls_for_recent_events(conn, limit_events=20)
        elif choice == "7":
            analyze_identity_changes(conn, limit=100)
        elif choice == "8":
            show_password_changes(conn, limit=10)
        elif choice == "9":
            show_alerts(conn, limit=20)
        else:
            print("Invalid choice. Please select 1-9.\n")

    conn.close()


if __name__ == "__main__":
    main()