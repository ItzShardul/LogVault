"""
blockchain.py
--------------
A small, self-contained, educational blockchain.

This is NOT Bitcoin/Ethereum. There is no mining, no consensus, no peer
network, and no economic incentive layer. It exists purely to demonstrate
one idea:

    Each block cryptographically commits to (a) the data it carries and
    (b) the hash of the block before it. That second link is what makes
    the chain tamper-evident: change anything in block N, and block N's
    own hash no longer matches what block N+1 says it should be.

Block hash formula (as specified in the project brief):

    block_hash = SHA256(index + timestamp + log_id + log_hash + previous_hash)
"""

import hashlib
from datetime import datetime, timezone

import database

GENESIS_LOG_ID = "GENESIS"
GENESIS_LOG_HASH = "0" * 64
GENESIS_PREVIOUS_HASH = "0" * 64


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_block_hash(index, timestamp, log_id, log_hash, previous_hash) -> str:
    payload = f"{index}{timestamp}{log_id}{log_hash}{previous_hash}"
    return sha256(payload)


def compute_log_hash(event_id, timestamp, source_ip, username, event_type,
                      severity, description) -> str:
    """Canonical hash of a log's contents, per the project spec."""
    payload = f"{event_id}{timestamp}{source_ip}{username}{event_type}{severity}{description}"
    return sha256(payload)


def ensure_genesis_block():
    """Create the genesis block if the chain is empty."""
    if database.count_blocks() == 0:
        timestamp = datetime.now(timezone.utc).isoformat()
        block_hash = compute_block_hash(
            0, timestamp, GENESIS_LOG_ID, GENESIS_LOG_HASH, GENESIS_PREVIOUS_HASH
        )
        database.insert_block(
            index=0,
            timestamp=timestamp,
            log_id=GENESIS_LOG_ID,
            log_hash=GENESIS_LOG_HASH,
            previous_hash=GENESIS_PREVIOUS_HASH,
            block_hash=block_hash,
        )
        database.add_activity("Genesis block created.", "info")


def add_block(log_id: str, log_hash: str) -> dict:
    """Append a new block that fingerprints the given log."""
    ensure_genesis_block()
    latest = database.get_latest_block()
    index = latest["block_index"] + 1
    previous_hash = latest["block_hash"]
    timestamp = datetime.now(timezone.utc).isoformat()
    block_hash = compute_block_hash(index, timestamp, log_id, log_hash, previous_hash)

    database.insert_block(
        index=index,
        timestamp=timestamp,
        log_id=log_id,
        log_hash=log_hash,
        previous_hash=previous_hash,
        block_hash=block_hash,
    )

    return {
        "index": index,
        "timestamp": timestamp,
        "log_id": log_id,
        "log_hash": log_hash,
        "previous_hash": previous_hash,
        "block_hash": block_hash,
    }


def validate_chain():
    """
    Walk the whole chain and check two things for every block:
      1. previous_hash actually equals the prior block's block_hash
      2. block_hash actually equals SHA256(index+timestamp+log_id+log_hash+previous_hash)

    Returns a dict describing overall chain validity and any broken links.
    """
    blocks = database.get_all_blocks()
    broken_links = []

    for i, block in enumerate(blocks):
        expected_hash = compute_block_hash(
            block["block_index"], block["timestamp"], block["log_id"],
            block["log_hash"], block["previous_hash"]
        )
        hash_ok = (expected_hash == block["block_hash"])

        if i == 0:
            link_ok = (block["previous_hash"] == GENESIS_PREVIOUS_HASH)
            expected_prev = GENESIS_PREVIOUS_HASH
        else:
            expected_prev = blocks[i - 1]["block_hash"]
            link_ok = (block["previous_hash"] == expected_prev)

        if not hash_ok or not link_ok:
            broken_links.append({
                "block_index": block["block_index"],
                "log_id": block["log_id"],
                "hash_ok": hash_ok,
                "link_ok": link_ok,
                "expected_previous_hash": expected_prev,
                "current_previous_hash": block["previous_hash"],
                "expected_block_hash": expected_hash,
                "current_block_hash": block["block_hash"],
            })

    return {
        "valid": len(broken_links) == 0,
        "total_blocks": len(blocks),
        "broken_links": broken_links,
    }
