"""
ids_simulator.py
-----------------
Generates realistic-looking but entirely fake security/IDS events.
No real network activity, no real hosts, no real credentials are ever
touched. Every IP, username, and "attack" here is synthetic data used
solely to exercise the logging + blockchain pipeline.
"""

import random
from datetime import datetime, timezone

EVENT_TYPES = {
    "LOGIN_SUCCESS":          "LOW",
    "LOGIN_FAILED":           "LOW",
    "PORT_SCAN":              "MEDIUM",
    "BRUTE_FORCE":            "HIGH",
    "SUSPICIOUS_FILE_ACCESS": "HIGH",
    "UNAUTHORIZED_LOGIN":     "HIGH",
    "PRIVILEGE_ESCALATION":   "CRITICAL",
    "MALWARE_DETECTED":       "CRITICAL",
}

DESCRIPTIONS = {
    "LOGIN_SUCCESS":          "User authenticated successfully",
    "LOGIN_FAILED":           "Authentication attempt failed",
    "PORT_SCAN":              "Sequential connection attempts across multiple ports detected",
    "BRUTE_FORCE":            "Multiple failed login attempts detected in a short window",
    "SUSPICIOUS_FILE_ACCESS": "Unusual access pattern detected on a sensitive file path",
    "UNAUTHORIZED_LOGIN":     "Login detected from an unrecognized source outside normal policy",
    "PRIVILEGE_ESCALATION":   "Account permissions elevated unexpectedly",
    "MALWARE_DETECTED":       "Signature matching known malicious behavior detected",
}

USERNAMES = ["admin", "jsmith", "svc_backup", "mchen", "root", "guest", "dbadmin", "kwilliams"]

_event_counter = 0


def _next_event_id():
    global _event_counter
    _event_counter += 1
    return f"EVT-{_event_counter:03d}"


def sync_counter_with(existing_event_ids):
    """Make sure freshly generated IDs never collide with ones already in the DB."""
    global _event_counter
    max_seen = 0
    for eid in existing_event_ids:
        try:
            n = int(eid.split("-")[-1])
            max_seen = max(max_seen, n)
        except (ValueError, IndexError):
            continue
    _event_counter = max(_event_counter, max_seen)


def _random_ip():
    # Private/reserved ranges only — never a routable public address.
    return f"192.168.{random.randint(1, 20)}.{random.randint(2, 254)}"


def generate_event(event_type=None, severity_bias=None):
    """
    Generate a single fake security event.
    If event_type is not given, pick one at random (optionally biased toward
    a severity tier for demo purposes).
    """
    if event_type is None:
        if severity_bias:
            candidates = [k for k, v in EVENT_TYPES.items() if v == severity_bias]
            event_type = random.choice(candidates or list(EVENT_TYPES))
        else:
            # Weighted so most traffic looks "normal"
            event_type = random.choices(
                population=list(EVENT_TYPES.keys()),
                weights=[30, 20, 15, 10, 8, 8, 5, 4],
                k=1
            )[0]

    severity = EVENT_TYPES[event_type]
    description = DESCRIPTIONS[event_type]

    return {
        "event_id": _next_event_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": _random_ip(),
        "username": random.choice(USERNAMES),
        "event_type": event_type,
        "severity": severity,
        "description": description,
    }


def generate_intrusion():
    """Generate a single high-severity/critical event, for demo purposes."""
    return generate_event(severity_bias=random.choice(["HIGH", "CRITICAL"]))
