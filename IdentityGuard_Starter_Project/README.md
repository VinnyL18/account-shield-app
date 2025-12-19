# IdentityGuard (v0.1)

IdentityGuard is a starter security-email scanner that pulls recent
"security alert" emails from your inbox, normalizes them into events,
assigns a simple risk score, stores them in a local database, and lets
you review results in a CLI dashboard.

## v0.1 Goals (MVP)

-   Fetch recent security-related emails via IMAP
-   Parse emails into normalized security events
-   Provider-aware classification (Apple, Google, Microsoft, Amazon +
    generic fallback)
-   Risk scoring (low / medium / high)
-   Store events in a local SQLite database
-   CLI dashboard for viewing results
-   Optional debug output for development

## Features

### Email scanning

-   Secure IMAP connection
-   Defensive handling of empty or malformed messages
-   Configurable message limits

### Parsing & normalization

Each email becomes a structured event containing: - Provider - Service
name - Event type (password change, new device login, suspicious
activity, etc.) - Risk level - IP / location / device (best-effort
extraction) - Timestamp - Raw subject and snippet - Message UID

### Risk scoring

-   Simple rules-based scoring
-   Provider-specific classifiers override generic classification

### Storage

-   SQLite database (`identityguard.db`)

### CLI dashboard

-   Risk summary
-   Recent events
-   High-risk events
-   Password change events
-   Critical alerts (if enabled)

## Requirements

-   Python 3.11+
-   IMAP-enabled email account
-   App password recommended

## How to Run

### Run scanner

``` bash
python run_identity_guard.py
```

### Run dashboard

``` bash
python cli_dashboard.py
```

## Debug Logging

When debug mode is enabled, IdentityGuard prints additional information
about: - Sender detection - Provider classification - Risk decisions

## Known Limitations (v0.1)

-   Keyword-based classifiers (not ML)
-   Limited provider coverage
-   CLI-only interface
-   No alert notifications

## Roadmap

### v0.2

-   More providers (PayPal, banks, social)
-   Improved IMAP search criteria
-   Stronger deduplication
-   Better parsing patterns

### v0.3

-   Logging to file
-   Debug mode toggle
-   Unit tests for classifiers

### v1.0

-   Web or desktop UI
-   Notifications
-   Advanced anomaly detection

------------------------------------------------------------------------

Current version: **v0.1**
