#!/usr/bin/env python3

import json
import os
import ssl
import urllib.request
from datetime import datetime, timezone

from pymongo import MongoClient
from pymongo.errors import PyMongoError

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB", "melissae")

CERTS_DIR = os.getenv("MELISSAE_CERTS_DIR",
                       os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pki", "ca"))

MANAGER_CERT = os.path.join(CERTS_DIR, "certs", "manager", "manager.crt")
MANAGER_KEY = os.path.join(CERTS_DIR, "certs", "manager", "manager.key")
CA_CERT = os.path.join(CERTS_DIR, "ca.crt")

TIMEOUT = 10
# Build mTLS SSL context for agent health checks
def create_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(MANAGER_CERT, MANAGER_KEY)
    ctx.load_verify_locations(CA_CERT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx

# Poll a single agent and update its health status
def poll_agent(agent: dict, ssl_ctx: ssl.SSLContext) -> dict:
    host = agent.get("host", "")
    port = agent.get("health_port", 8444)
    agent_id = agent.get("agent_id", "unknown")
    url = f"https://{host}:{port}/health"

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl_ctx) as resp:
            data = json.loads(resp.read())
            return {
                "status": data.get("status", "healthy"),
                "last_health": data,
                "last_check": datetime.now(timezone.utc).isoformat(),
                "error": None,
            }
    except Exception as e:
        print(f"[health_poller] Agent {agent_id} ({host}:{port}) unreachable: {e}")
        return {
            "status": "unreachable",
            "last_check": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
        }

# Entry point — poll agents on a regular interval
def main():
    try:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        agents = list(db["agents"].find({"host": {"$exists": True}}))
    except PyMongoError as e:
        print(f"[health_poller] MongoDB error: {e}")
        return

    if not agents:
        return

    for path in [MANAGER_CERT, MANAGER_KEY, CA_CERT]:
        if not os.path.isfile(path):
            print(f"[health_poller] Missing cert file: {path}")
            return

    ssl_ctx = create_ssl_context()

    for agent in agents:
        agent_id = agent.get("agent_id", "")
        if not agent_id:
            continue

        result = poll_agent(agent, ssl_ctx)

        try:
            db["agents"].update_one(
                {"agent_id": agent_id},
                {"$set": result}
            )
        except PyMongoError as e:
            print(f"[health_poller] Update error for {agent_id}: {e}")

if __name__ == "__main__":
    main()

