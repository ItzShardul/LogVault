"""
app.py
------
Flask backend for LogVault.

Educational cybersecurity simulation only. See README.md for scope and
safety notes. All events, IPs, and "attacks" are synthetic and operate
solely on this application's own local SQLite database.
"""

import random
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, request, render_template

import database
import blockchain
import ids_simulator

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Bootstrapping
# ---------------------------------------------------------------------------

def bootstrap():
    database.init_db(reset=False)
    blockchain.ensure_genesis_block()
    existing = [l["event_id"] for l in database.get_all_logs()]
    ids_simulator.sync_counter_with(existing)


bootstrap()


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _record_event(event):
    """Hash a generated event, store it locally, and commit it to the chain."""
    log_hash = blockchain.compute_log_hash(
        event["event_id"], event["timestamp"], event["source_ip"],
        event["username"], event["event_type"], event["severity"],
        event["description"]
    )
    database.insert_log(
        event_id=event["event_id"],
        timestamp=event["timestamp"],
        source_ip=event["source_ip"],
        username=event["username"],
        event_type=event["event_type"],
        severity=event["severity"],
        description=event["description"],
        log_hash=log_hash,
    )
    block = blockchain.add_block(event["event_id"], log_hash)
    return log_hash, block


def _verify_log(log):
    """
    Verify a single local log against its blockchain record.
    Returns a result dict; does not touch broken-chain detection (that's
    handled separately at the chain level).
    """
    recalculated_hash = blockchain.compute_log_hash(
        log["event_id"], log["timestamp"], log["source_ip"],
        log["username"], log["event_type"], log["severity"], log["description"]
    )
    block = database.get_block_by_log_id(log["event_id"])

    if block is None:
        return {
            "event_id": log["event_id"],
            "result": "NO_BLOCKCHAIN_RECORD",
            "local_hash": recalculated_hash,
            "blockchain_hash": None,
            "stored_hash": log["log_hash"],
        }

    if recalculated_hash == block["log_hash"]:
        result = "AUTHENTIC"
    else:
        result = "MODIFIED"

    return {
        "event_id": log["event_id"],
        "result": result,
        "local_hash": recalculated_hash,
        "blockchain_hash": block["log_hash"],
        "stored_hash": log["log_hash"],
        "block_index": block["block_index"],
    }


def run_verification():
    """Full integrity sweep: every local log + every blockchain log_id."""
    logs = database.get_all_logs()
    blocks = [b for b in database.get_all_blocks() if b["log_id"] != blockchain.GENESIS_LOG_ID]

    logs_by_event_id = {l["event_id"]: l for l in logs}
    results = []

    # 1. Check every local log against its block (authentic / modified)
    for log in logs:
        results.append(_verify_log(log))

    # 2. Check every block that has no corresponding local log (deleted)
    for block in blocks:
        if block["log_id"] not in logs_by_event_id:
            results.append({
                "event_id": block["log_id"],
                "result": "DELETED",
                "local_hash": None,
                "blockchain_hash": block["log_hash"],
                "stored_hash": None,
                "block_index": block["block_index"],
            })

    chain_status = blockchain.validate_chain()

    summary = {
        "total_events": len(results),
        "authentic": sum(1 for r in results if r["result"] == "AUTHENTIC"),
        "modified": sum(1 for r in results if r["result"] == "MODIFIED"),
        "deleted": sum(1 for r in results if r["result"] == "DELETED"),
        "no_blockchain_record": sum(1 for r in results if r["result"] == "NO_BLOCKCHAIN_RECORD"),
        "chain_valid": chain_status["valid"],
    }

    return {
        "results": sorted(results, key=lambda r: r["event_id"]),
        "chain_status": chain_status,
        "summary": summary,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# API: event generation
# ---------------------------------------------------------------------------

@app.route("/api/generate_event", methods=["POST"])
def api_generate_event():
    event = ids_simulator.generate_event()
    log_hash, block = _record_event(event)
    database.add_activity(
        f"IDS generated {event['event_type']} ({event['severity']}) — {event['event_id']} secured in block #{block['index']}",
        "info"
    )
    return jsonify({"event": event, "log_hash": log_hash, "block": block})


@app.route("/api/generate_batch", methods=["POST"])
def api_generate_batch():
    count = int((request.get_json(silent=True) or {}).get("count", 5))
    count = max(1, min(count, 50))
    created = []
    for _ in range(count):
        event = ids_simulator.generate_event()
        log_hash, block = _record_event(event)
        created.append(event)
    database.add_activity(f"Generated {count} baseline security events.", "info")
    return jsonify({"events": created})


@app.route("/api/generate_intrusion", methods=["POST"])
def api_generate_intrusion():
    event = ids_simulator.generate_intrusion()
    log_hash, block = _record_event(event)
    database.add_activity(
        f"IDS flagged intrusion: {event['event_type']} from {event['source_ip']} — {event['event_id']}",
        "alert"
    )
    return jsonify({"event": event, "log_hash": log_hash, "block": block})


# ---------------------------------------------------------------------------
# API: read state
# ---------------------------------------------------------------------------

@app.route("/api/logs", methods=["GET"])
def api_logs():
    return jsonify({"logs": database.get_all_logs()})


@app.route("/api/blockchain", methods=["GET"])
def api_blockchain():
    return jsonify({"blocks": database.get_all_blocks()})


@app.route("/api/activity", methods=["GET"])
def api_activity():
    return jsonify({"activity": database.get_activity()})


@app.route("/api/stats", methods=["GET"])
def api_stats():
    logs = database.get_all_logs()
    blocks = database.get_all_blocks()
    verification = run_verification()
    stats = {
        "total_events": len(logs),
        "critical_events": sum(1 for l in logs if l["severity"] == "CRITICAL"),
        "blockchain_blocks": len(blocks),
        "verified_logs": verification["summary"]["authentic"],
        "tampered_logs": verification["summary"]["modified"],
        "missing_logs": verification["summary"]["deleted"],
        "chain_valid": verification["summary"]["chain_valid"],
    }
    return jsonify({"stats": stats})


# ---------------------------------------------------------------------------
# API: verification
# ---------------------------------------------------------------------------

@app.route("/api/verify", methods=["POST"])
def api_verify():
    report = run_verification()
    if report["summary"]["modified"] or report["summary"]["deleted"] or not report["summary"]["chain_valid"]:
        database.add_activity("Verification sweep completed — issues found.", "alert")
    else:
        database.add_activity("Verification sweep completed — all logs authentic.", "success")
    return jsonify(report)


# ---------------------------------------------------------------------------
# API: attacker simulation
# (All actions below operate ONLY on this app's own local SQLite database.
#  Nothing here touches a real network, host, or credential.)
# ---------------------------------------------------------------------------

@app.route("/api/attack/modify", methods=["POST"])
def api_attack_modify():
    body = request.get_json(silent=True) or {}
    event_id = body.get("event_id")
    field = body.get("field", "severity")
    user_value = body.get("value")  # explicit value chosen by the person, if any

    log = database.get_log_by_event_id(event_id) if event_id else None
    if log is None:
        logs = database.get_all_logs()
        if not logs:
            return jsonify({"error": "No logs available to attack."}), 400
        log = random.choice(logs)
        event_id = log["event_id"]

    random_values = {
        "severity": lambda: random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
        "timestamp": lambda: datetime.now(timezone.utc).isoformat(),
        "username": lambda: random.choice(["root", "backdoor_user", "anonymous"]),
        "description": lambda: "Routine system check completed successfully.",
        "source_ip": lambda: f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",
    }
    if field not in random_values:
        field = "severity"

    old_value = log[field]

    if user_value is not None and str(user_value).strip() != "":
        new_value = str(user_value).strip()
    else:
        new_value = random_values[field]()
        while new_value == old_value:
            new_value = random_values[field]()

    database.update_log_field(event_id, field, new_value)
    database.add_activity(
        f"⚠ Attacker modified log {event_id}: {field} changed from '{old_value}' to '{new_value}'",
        "attack"
    )

    return jsonify({
        "event_id": event_id,
        "field": field,
        "old_value": old_value,
        "new_value": new_value,
    })


@app.route("/api/attack/change_timestamp", methods=["POST"])
def api_attack_timestamp():
    body = request.get_json(silent=True) or {}
    event_id = body.get("event_id")
    user_value = body.get("value")

    log = database.get_log_by_event_id(event_id) if event_id else None
    if log is None:
        logs = database.get_all_logs()
        if not logs:
            return jsonify({"error": "No logs available to attack."}), 400
        log = random.choice(logs)
        event_id = log["event_id"]

    old_value = log["timestamp"]
    if user_value is not None and str(user_value).strip() != "":
        new_value = str(user_value).strip()
    else:
        new_value = datetime.now(timezone.utc).isoformat()
    database.update_log_field(event_id, "timestamp", new_value)
    database.add_activity(
        f"⚠ Attacker altered timestamp on {event_id} to conceal the true time of the event.",
        "attack"
    )
    return jsonify({"event_id": event_id, "old_value": old_value, "new_value": new_value})


@app.route("/api/attack/delete", methods=["POST"])
def api_attack_delete():
    body = request.get_json(silent=True) or {}
    event_id = body.get("event_id")
    log = database.get_log_by_event_id(event_id) if event_id else None
    if log is None:
        logs = database.get_all_logs()
        if not logs:
            return jsonify({"error": "No logs available to attack."}), 400
        log = random.choice(logs)
        event_id = log["event_id"]

    database.delete_log(event_id)
    database.add_activity(f"⚠ Attacker deleted local log {event_id} to erase evidence.", "attack")
    return jsonify({"event_id": event_id, "deleted": True})


@app.route("/api/attack/tamper_blockchain", methods=["POST"])
def api_attack_tamper_blockchain():
    body = request.get_json(silent=True) or {}
    block_index = body.get("block_index")
    user_value = body.get("value")

    blocks = database.get_all_blocks()
    real_blocks = [b for b in blocks if b["block_index"] != 0]  # never target genesis
    if not real_blocks:
        return jsonify({"error": "No blocks available to attack."}), 400

    if block_index is None:
        target = random.choice(real_blocks)
    else:
        target = next((b for b in blocks if b["block_index"] == block_index), None)
        if target is None:
            return jsonify({"error": "Block not found."}), 404

    old_prev_hash = target["previous_hash"]
    if user_value is not None and str(user_value).strip() != "":
        fake_prev_hash = str(user_value).strip()
    else:
        fake_prev_hash = blockchain.sha256(f"forged-{time.time()}")
    database.update_block_field(target["block_index"], "previous_hash", fake_prev_hash)

    database.add_activity(
        f"⚠ Attacker tampered with Block #{target['block_index']} — rewrote previous_hash to hide a change.",
        "attack"
    )

    return jsonify({
        "block_index": target["block_index"],
        "old_previous_hash": old_prev_hash,
        "new_previous_hash": fake_prev_hash,
    })


# ---------------------------------------------------------------------------
# API: reset + demo
# ---------------------------------------------------------------------------

@app.route("/api/reset", methods=["POST"])
def api_reset():
    database.init_db(reset=True)
    blockchain.ensure_genesis_block()
    ids_simulator.sync_counter_with([])
    database.add_activity("System reset. Genesis block re-initialized.", "info")
    return jsonify({"reset": True})


@app.route("/api/demo", methods=["POST"])
def api_demo():
    """
    Run the full attack demo sequence server-side and return every step's
    result, so the frontend can narrate the story beat by beat.
    """
    steps = []

    # 1-2. Generate several normal logs + one simulated intrusion
    normal_events = []
    for _ in range(5):
        event = ids_simulator.generate_event()
        _record_event(event)
        normal_events.append(event)
    steps.append({"step": "Generated baseline traffic", "detail": f"{len(normal_events)} normal events logged and hashed."})

    intrusion = ids_simulator.generate_intrusion()
    _record_event(intrusion)
    steps.append({"step": "Simulated intrusion", "detail": f"{intrusion['event_type']} detected — {intrusion['event_id']}"})

    # 3-5. Already stored + hashed + chained above.
    steps.append({"step": "Logs hashed with SHA-256 and committed to the blockchain", "detail": f"{blockchain.compute_log_hash.__name__} applied to each event."})

    # 6. Verify everything (should be clean)
    pre_attack_report = run_verification()
    steps.append({"step": "Initial verification", "detail": f"{pre_attack_report['summary']['authentic']} logs authentic, chain valid: {pre_attack_report['summary']['chain_valid']}"})

    # 7-9. Attacker modifies one log and deletes another
    logs = database.get_all_logs()
    if len(logs) >= 2:
        modify_target, delete_target = random.sample(logs, 2)
    else:
        modify_target = delete_target = logs[0]

    old_severity = modify_target["severity"]
    new_severity = "LOW" if old_severity != "LOW" else "MEDIUM"
    database.update_log_field(modify_target["event_id"], "severity", new_severity)
    database.add_activity(
        f"⚠ [DEMO] Attacker modified {modify_target['event_id']}: severity {old_severity} → {new_severity}",
        "attack"
    )
    steps.append({
        "step": "Attacker modifies a log",
        "detail": f"{modify_target['event_id']} severity changed from {old_severity} to {new_severity} (blockchain record left untouched)."
    })

    database.delete_log(delete_target["event_id"])
    database.add_activity(f"⚠ [DEMO] Attacker deleted local log {delete_target['event_id']}", "attack")
    steps.append({
        "step": "Attacker deletes a log",
        "detail": f"{delete_target['event_id']} removed from local storage (blockchain record still exists)."
    })

    # 10-11. Verify again and report tampering
    post_attack_report = run_verification()
    database.add_activity("Post-attack verification sweep completed.", "alert")
    steps.append({
        "step": "Post-attack verification",
        "detail": f"{post_attack_report['summary']['modified']} modified, {post_attack_report['summary']['deleted']} deleted detected."
    })

    return jsonify({
        "steps": steps,
        "modified_event_id": modify_target["event_id"],
        "deleted_event_id": delete_target["event_id"],
        "pre_attack_report": pre_attack_report,
        "post_attack_report": post_attack_report,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
