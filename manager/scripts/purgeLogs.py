import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from pymongo import MongoClient
from pymongo.errors import PyMongoError

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB", "melissae")

LOG_RETENTION_DAYS = int(os.getenv("MELISSAE_LOG_RETENTION_DAYS", "30"))
BENIGN_THREAT_IDLE_HOURS = int(os.getenv("MELISSAE_BENIGN_IDLE_HOURS", "1"))

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

def purge_benign_threats():
    cutoff = datetime.now(timezone.utc) - timedelta(hours=BENIGN_THREAT_IDLE_HOURS)
    try:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]

        benign_iocs = list(db["threats"].find({"verdict": "benign"}, {"ip": 1, "_id": 0}))
        if not benign_iocs:
            return

        purged = 0
        for doc in benign_iocs:
            ip = doc.get("ip")
            if not ip:
                continue

            last_seen = get_last_seen(db, ip)
            if last_seen is None or last_seen < cutoff:
                try:
                    db["threats"].delete_one({"ip": ip})
                    purged += 1
                except PyMongoError as e:
                    print(f"[purge_iocs] Error purging threat {ip}: {e}")
        if purged:
            print(f"[purge_iocs] Recycled {purged} idle benign threat doc(s)")
    except PyMongoError as e:
        print(f"[purge_iocs] Mongo error: {e}")

def purge_old_logs():
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOG_RETENTION_DAYS)
    cutoff_iso = cutoff.isoformat(timespec="microseconds").replace("+00:00", "Z")
    try:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        result = db["logs"].delete_many({"timestamp": {"$lt": cutoff_iso}})
        if result.deleted_count:
            print(f"[purge_iocs] Deleted {result.deleted_count} log(s) older than "
                  f"{LOG_RETENTION_DAYS}d (cutoff {cutoff_iso})")
    except PyMongoError as e:
        print(f"[purge_iocs] Log purge error: {e}")


if __name__ == "__main__":
    purge_benign_threats()
    purge_old_logs()

