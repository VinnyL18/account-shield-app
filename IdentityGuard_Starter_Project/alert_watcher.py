import time
from db import get_conn  # uses the same DB helper as the rest of the project


def fetch_undelivered_alerts(conn):
    """Return all alerts that haven't been marked delivered yet."""
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            alerts.id,
            events.event_type,
            events.time_utc,
            events.service,
            events.account_email,
            events.ip,
            events.location
        FROM alerts
        JOIN events ON alerts.event_id = events.id
        WHERE alerts.delivered = 0
        ORDER BY alerts.id ASC
        """
    )
    return cur.fetchall()


def mark_alerts_delivered(conn, alert_ids):
    """Set delivered=1 for the given alert IDs."""
    if not alert_ids:
        return

    cur = conn.cursor()
    placeholders = ",".join("?" for _ in alert_ids)
    sql = f"UPDATE alerts SET delivered = 1 WHERE id IN ({placeholders})"
    cur.execute(sql, alert_ids)
    conn.commit()


def main():
    print("=== IdentityGuard Alert Watcher ===")
    print("Watching for new CRITICAL alerts... (Ctrl+C to stop)\n")

    try:
        while True:
            with get_conn() as conn:
                alerts = fetch_undelivered_alerts(conn)

                if alerts:
                    for (
                        alert_id,
                        event_type,
                        time_utc,
                        service,
                        account_email,
                        ip,
                        location,
                    ) in alerts:
                        acct = account_email or "unknown account"
                        ip_str = ip or "-"
                        loc_str = location or "-"

                        print(
                            f"[ALERT {alert_id}] {event_type.upper()} at {time_utc} "
                            f"on {service} ({acct})  IP={ip_str}  LOC={loc_str}"
                        )

                    # Mark them delivered so we don't print twice
                    mark_alerts_delivered(conn, [a[0] for a in alerts])

            # Check every 10 seconds (tweak if you want)
            time.sleep(10)

    except KeyboardInterrupt:
        print("\nStopping alert watcher.")


if __name__ == "__main__":
    main()