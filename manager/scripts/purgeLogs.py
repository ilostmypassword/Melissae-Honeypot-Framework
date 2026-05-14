import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from pymongo import MongoClient
from pymongo.errors import PyMongoError

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB", "melissae")

# Parse a timestamp from various log formats
def parse_timestamp(log: dict) -> Optional[datetime]:
    if not log:
        return None
    raw_ts = log.get("timestamp") or log.get("time") or log.get("datetime")
    if raw_ts:
        try:
            raw = str(raw_ts).strip().replace("Z", "+00:00").replace(" ", "T", 1)
            dt = datetime.fromisoformat(raw)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        except ValueError:
            pass

    date = log.get("date")
    hour = log.get("hour")
    if date and hour:
        try:
            raw = f"{date}T{hour}".replace("Z", "+00:00")
            dt = datetime.fromisoformat(raw)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        except ValueError:
            pass
        try:
            return datetime.strptime(f"{date} {str(hour)[:8]}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None

# Get the most recent log timestamp for an IP
def get_last_seen(db, ip: str) -> Optional[datetime]:
    try:
        doc = db["logs"].find_one(
            {"ip": ip},
            {"timestamp": 1, "date": 1, "hour": 1, "_id": 0},
            sort=[("timestamp", -1)],
        )
        return parse_timestamp(doc) if doc else None
    except PyMongoError as e:
        print(f"[purge_iocs] Error fetching logs for {ip}: {e}")
        return None

# Remove benign IPs and their logs if unseen for 1 hour
def purge_benign_older_than_1h():
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
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

