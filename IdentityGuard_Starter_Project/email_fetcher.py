"""
email_fetcher.py – IMAP client for fetching security emails.
"""

import imaplib
import email
from email.message import Message
from typing import List, Tuple, Optional


class EmailFetcher:
    def __init__(self, host: str, port: int, username: str, password: str, provider: str = "gmail"):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.provider = provider
        self._imap: Optional[imaplib.IMAP4_SSL] = None

    def connect(self) -> None:
        self._imap = imaplib.IMAP4_SSL(self.host, self.port)
        self._imap.login(self.username, self.password)

    def close(self) -> None:
        if self._imap is not None:
            try:
                self._imap.logout()
            except Exception:
                pass
            self._imap = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def fetch_security_messages(self, max_messages: int = 50) -> List[Tuple[str, Message]]:
        """
        Fetch up to `max_messages` security-related messages from the INBOX.

        Returns a list of (id, email.message.Message).
        """
        if self._imap is None:
            raise RuntimeError("Not connected")

        # Select the INBOX first (required by Yahoo and others)
        self._imap.select("INBOX")

        # Basic search query focused on common security alert senders.
        # You can extend this as needed.
        if self.provider == "gmail":
            search_criteria = (
                '(OR FROM "no-reply@accounts.google.com" '
                'FROM "security-noreply@account.microsoft.com")'
            )
        else:
            # Fallback – for Yahoo we just scan all recent messages
            search_criteria = "ALL"

        # Use standard SEARCH instead of UID SEARCH for better compatibility
        result, data = self._imap.search(None, search_criteria)
        if result != "OK":
            print("IMAP search failed:", result, data)
            return []

        ids = data[0].split()
        # Take the most recent N
        ids = ids[-max_messages:]

        messages: List[Tuple[str, Message]] = []
        for msg_id in ids:
            res, msg_data = self._imap.fetch(msg_id, "(RFC822)")
            if res != "OK" or not msg_data or msg_data[0] is None:
                continue

            raw = msg_data[0][1]
            if raw is None:
                continue

            msg = email.message_from_bytes(raw)
            messages.append((msg_id.decode(), msg))

        return messages
