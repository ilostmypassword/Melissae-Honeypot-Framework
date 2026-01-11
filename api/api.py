from flask import Flask, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.errors import PyMongoError
import os
from datetime import datetime

app = Flask(__name__)
# Restrict CORS to dashboard/forwarded origins
CORS(app, resources={r"/api/*": {"origins": [
    "http://localhost:9999",
    "http://127.0.0.1:9999",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
]}})

MONGO_URI = os.getenv("MONGO_URI", "mongodb://melissae_mongo:27017")
DB_NAME = os.getenv("MONGO_DB", "melissae")


def get_db():
    client = MongoClient(MONGO_URI)
    return client[DB_NAME]

# Logs route
@app.route("/api/logs", methods=["GET"])
def api_logs():
    try:
        db = get_db()
        data = list(db["logs"].find({}, {"_id": 0}))
        return jsonify(data)
    except PyMongoError as e:
        return jsonify({"error": str(e)}), 500

# Threats route
@app.route("/api/threats", methods=["GET"])
def api_threats():
    try:
        db = get_db()
        data = list(db["threats"].find({}, {"_id": 0}))
        return jsonify(data)
    except PyMongoError as e:
        return jsonify({"error": str(e)}), 500

# Killchain route for a specific IP
@app.route("/api/threats/<ip>/killchain", methods=["GET"])
def api_killchain(ip):
    try:
        db = get_db()
        logs = list(db["logs"].find({"ip": ip}, {"_id": 0}))

        events = []
        for log in logs:
            ts_str = log.get("timestamp")
            dt = None

            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str)
                except ValueError:
                    dt = None

            if not dt and log.get("date") and log.get("hour"):
                ts_str = f"{log['date']} {log['hour']}"
                try:
                    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    dt = None

            if not dt and log.get("date"):
                ts_str = log.get("date")
                try:
                    dt = datetime.fromisoformat(ts_str)
                except ValueError:
                    dt = None

            event = {
                "timestamp": dt.isoformat() if dt else ts_str,
                "protocol": log.get("protocol", "other"),
                "action": log.get("action"),
                "path": log.get("path"),
                "user": log.get("user"),
                "user-agent": log.get("user-agent"),
            }
            events.append((dt.timestamp() if dt else float("inf"), event))

        events.sort(key=lambda x: x[0])
        ordered = [e for _, e in events]

        return jsonify({"ip": ip, "events": ordered})
    except PyMongoError as e:
        return jsonify({"error": str(e)}), 500

# Main
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
