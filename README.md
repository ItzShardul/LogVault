# LogVault — Blockchain-Based Tamper-Proof Security Log Simulator

LogVault is an educational demonstration of a well-known blockchain use case
outside of cryptocurrency: **using a hash chain to make tampering with a
security log detectable**, even when the log file itself is fully editable
by whoever compromises the machine it lives on.

> ⚠️ **This is a simulation.** No real network, host, or credential is ever
> touched. All IDS "events" and IP addresses are synthetic, and every
> "attack" in this project modifies only this application's own local
> SQLite database.

---

## 1. Problem statement

Intrusion Detection Systems (IDS), firewalls, and audit trails all produce
logs that are the primary evidence used to understand a breach after the
fact. But logs usually live as ordinary files or database rows on the same
systems an attacker is trying to compromise. Once an attacker gets
administrative access, they can:

- edit a log entry to downgrade its severity or change its details,
- edit a timestamp to build a false timeline,
- delete the entry entirely.

If the only copy of "what happened" is a mutable file sitting next to the
attacker, that evidence cannot be trusted after a compromise.

## 2. Motivation

Blockchains are built around one specific, useful property: a chain of
records where changing any past record breaks a verifiable link to every
record after it. LogVault applies that property narrowly and honestly — not
to logs themselves, but to **fingerprints (hashes) of logs** — to show how
you can detect, after the fact, that a log was altered or removed, even
though the blockchain itself did nothing to physically stop the attacker
from touching the file.

## 3. Real-world relevance

This pattern (hash-chaining log fingerprints, sometimes called "log
notarization" or "tamper-evident logging") shows up in real systems:
write-once audit logs, certificate transparency logs, and compliance
systems that need to prove a record hasn't been quietly rewritten. Some SIEM
and audit-log products advertise "blockchain-backed" logs — this project
demonstrates, at a small and readable scale, what that actually means
under the hood.

## 4. System architecture

```
 Attack Simulator
       │
       ▼
 IDS Simulator ──► Security Event
       │
       ▼
 Log Manager ──SHA-256──┬──► Local Log Storage (SQLite: logs table)
                        │
                        └──► Mini Blockchain (SQLite: blockchain table)
                                    │
                                    ▼
                          Integrity Verifier
                                    │
                                    ▼
                          Security Dashboard (Flask + vanilla JS)
```

- `ids_simulator.py` — generates fake but realistic security events
  (`LOGIN_FAILED`, `BRUTE_FORCE`, `PRIVILEGE_ESCALATION`, etc.) with an
  assigned severity.
- `blockchain.py` — a small, self-contained hash-chain implementation
  (no mining, no peers, no cryptocurrency).
- `database.py` — SQLite persistence for logs, blockchain blocks, and an
  activity feed.
- `app.py` — Flask API that wires the above together and exposes the
  attacker-simulation and verification endpoints.
- `templates/`, `static/` — the dashboard UI.

## 5. How the blockchain works

Each block commits to two things: the log it fingerprints, and the hash of
the block immediately before it.

```
block_hash = SHA256(index + timestamp + log_id + log_hash + previous_hash)
```

The **first** block is a genesis block with `previous_hash` fixed to
`"0"*64`. Every later block's `previous_hash` field must equal the previous
block's `block_hash`. That link is what makes the chain tamper-evident:
if you change any field in an existing block, its own recomputed
`block_hash` no longer matches what's stored, **and** the next block's
`previous_hash` no longer matches the (changed) prior block either. Chain
validation (`blockchain.validate_chain()`) walks every block and checks
both conditions.

## 6. How SHA-256 is used

Every security event is hashed **twice**, for two different purposes:

1. **Log hash** — a fingerprint of the log's own content, calculated as:
   `SHA256(event_id + timestamp + source_ip + username + event_type + severity + description)`.
   This is stored both alongside the local log row and inside the
   blockchain block that references it.
2. **Block hash** — a fingerprint of the block itself (see above), which
   chains blocks together.

## 7. How log tampering is detected

When you run **Verify all logs**, LogVault recalculates the log hash from
the log's *current* field values and compares it to the log hash stored in
that log's blockchain block. If an attacker changed any field (severity,
timestamp, username, description, source IP), the recalculated hash will
no longer match the blockchain's recorded hash — an unmistakable
`MODIFIED` result, since the blockchain hash reflects the log's *original*
contents at the moment it was secured.

## 8. How log deletion is detected

If a local log row is deleted from SQLite, verification will find a
blockchain block whose `log_id` has no corresponding row in the `logs`
table. This is reported as `DELETED` — the cryptographic proof that the
event existed still exists on-chain, even though the actual log is gone.

## 9. How blockchain tampering is detected

The **Tamper blockchain** attack simulates an attacker going a step
further and editing the chain itself (e.g., rewriting a block's
`previous_hash`). `validate_chain()` catches this because:

- the edited block's `previous_hash` no longer equals the prior block's
  actual `block_hash` (a broken link), and/or
- the edited block's own `block_hash` no longer matches what
  `SHA256(index + timestamp + log_id + log_hash + previous_hash)` produces.

This is the core lesson of the demo: chaining blocks together means a
single edited block is detectable without needing a second, independent
copy of the chain — though in a **real** system you would still want the
chain replicated across independent nodes so an attacker with full access
to one machine can't rewrite the *entire* local chain to match their edit.
LogVault keeps everything on one machine for simplicity, which is a
deliberate simplification described in Limitations below.

## 10. Installation

Requires Python 3.9+.

```bash
cd logvault
pip install -r requirements.txt
```

## 11. Running the application

```bash
python3 app.py
```

Then open **http://localhost:5000** in a browser. The database
(`logvault.db`) and a genesis block are created automatically on first run.

## 12. Demonstration steps

**Guided walkthrough (recommended, ~1 minute):**

1. Open the app — the *Overview* tab shows an empty dashboard with a
   genesis block already created.
2. Go to **Attacker Simulation** and click **Run full attack demo**. This
   automatically generates baseline traffic and an intrusion, secures them
   on-chain, then modifies one log and deletes another, and re-verifies —
   narrating every step in an alert panel and landing you on the
   **Verification** tab with the results.

**Manual walkthrough (~3–5 minutes), for a deeper demo:**

1. **Overview** — click **Generate event** a few times, then
   **Simulate intrusion** once. Watch the stats and events table update.
2. **Blockchain** — see each new event has produced a chained block.
   Click a block to inspect its fields (hash, previous hash, timestamp).
3. **Verification** — click **Verify all logs**. Everything should read
   `AUTHENTIC` and the chain should be `VALID`.
4. **Attacker Simulation** — click **Modify log**. This silently changes a
   field on a random log without touching its blockchain record.
5. Go back to **Verification** and click **Verify all logs** again — the
   modified log now reports `MODIFIED`, with the local hash and blockchain
   hash shown side by side so the mismatch is visible.
6. Try **Delete log** the same way — verification will report `DELETED`
   for that event.
7. Try **Tamper blockchain** — verification will report the chain itself
   as `INVALID`, pointing at the specific block whose link is broken.
8. Click **Reset system** at any time to start over from a fresh genesis
   block.

## 13. Limitations

This is a proof-of-concept, not a production security tool:

- **Single machine, single copy.** The blockchain lives in the same
  SQLite file as the logs, on the same machine. A sufficiently privileged
  attacker could, in principle, rewrite the entire local chain to match
  their edited log (recomputing every subsequent block's hash). A real
  deployment needs the chain replicated to machines the attacker doesn't
  control (a **distributed or permissioned blockchain**, or at minimum a
  remote, write-once/append-only log shipping target), so that no single
  compromised host can update every copy.
- **No consensus or mining.** This is a linear hash chain, not a
  distributed ledger with independent validators — appropriate for
  teaching the core idea, not for adversarial multi-party trust.
- **No authentication/authorization layer.** Anyone with access to the
  running app can trigger the attacker-simulation endpoints; this is
  intentional for a demo tool, not something to expose publicly.
- **Simulated data only.** Events, IPs, and usernames are synthetic and
  are not derived from any real network traffic or IDS engine.
- **No secure timestamping.** Block timestamps come from the local system
  clock, not a trusted/external time source.

## 14. Possible future improvements

- Replicate the blockchain to multiple independent nodes (or an external
  service) so a single compromised host cannot rewrite history.
- Ship logs to write-once remote storage in addition to local SQLite.
- Add authenticated roles (viewer vs. admin) and remove/gate the attacker
  simulation endpoints in any non-demo deployment.
- Add real IDS log ingestion (e.g., parsing actual syslog/auth logs) behind
  the same hashing and chaining pipeline.
- Add digital signatures (not just hashes) so blocks can be attributed to
  a specific logging node.
- Persist the chain across restarts more robustly and add chain export/
  import for offline verification.

---

### Safety note

This project is strictly a **local simulation**. It does not scan real
networks, attack real IP addresses, execute malware, perform real
exploitation, or use real credentials. All "attacker" actions operate only
on this application's own SQLite database.
