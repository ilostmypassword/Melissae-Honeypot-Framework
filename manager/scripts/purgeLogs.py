import os
from datetime import datetime, timedelta
from typing import Optional

from pymongo import MongoClient
from pymongo.errors import PyMongoError

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB", "melissae")

# Parse a timestamp from various log formats
def parse_timestamp(log: dict) -> Optional[datetime]:
    raw_ts = log.get("timestamp") or log.get("time") or log.get("datetime")
    if raw_ts:
        try:
            dt = datetime.fromisoformat(raw_ts)
            return dt.replace(tzinfo=None) if dt.tzinfo else dt
        except ValueError:
            pass

    date = log.get("date")
    hour = log.get("hour")
    if date and hour:
        try:
            return datetime.strptime(f"{date} {hour}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    return None

# Get the most recent log timestamp for an IP
def get_last_seen(db, ip: str) -> Optional[datetime]:
    try:
        cursor = db["logs"].find({"ip": ip}, {"timestamp": 1, "date": 1, "hour": 1})
        last_seen = None
        for log in cursor:
            dt = parse_timestamp(log)
            if dt and (last_seen is None or dt > last_seen):
                last_seen = dt
        return last_seen
    except PyMongoError as e:
        print(f"[purge_iocs] Error fetching logs for {ip}: {e}")
        return None

# Remove benign IPs and their logs if unseen for 1 hour
def purge_benign_older_than_1h():
    cutoff = datetime.utcnow() - timedelta(hours=1)
    try:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]

        benign_iocs = list(db["threats"].find({"verdict": "benign"}, {"ip": 1, "_id": 0}))
        if not benign_iocs:
            return

        for doc in benign_iocs:
            ip = doc.get("ip")
            if not ip:
                continue

            last_seen = get_last_seen(db, ip)
            if last_seen is None or last_seen < cutoff:
                try:
                    db["threats"].delete_one({"ip": ip})
                    db["logs"].delete_many({"ip": ip})
                    print(f"[purge_iocs] Purged IP {ip} (last seen: {last_seen})")
                except PyMongoError as e:
                    print(f"[purge_iocs] Error purging {ip}: {e}")
    except PyMongoError as e:
        print(f"[purge_iocs] Mongo error: {e}")

if __name__ == "__main__":
    purge_benign_older_than_1h()

