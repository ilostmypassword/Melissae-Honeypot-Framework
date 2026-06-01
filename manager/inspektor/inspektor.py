#!/usr/bin/env python3

from __future__ import annotations

import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import yaml
import boto3
from flask import Flask, jsonify, request
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_aws import ChatBedrock
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from pymongo import MongoClient
from pymongo.errors import PyMongoError

import tools

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("inspektor")

BASE_DIR = Path(__file__).resolve().parent
REPORT_COLLECTION = "inspektor_report"

KICKOFF = "Produce the current threat briefing for the Melissae honeypot network."

IDLE_BRIEFING = (
    "## Threat Briefing\n\n"
    "**Posture:** Calm — no threats are currently tracked across the honeypot "
    "network.\n\n"
    "### Key Findings\n- No attacker activity has been recorded yet.\n\n"
    "### Recommended Actions\n- Keep the honeypots exposed and monitor for the "
    "first probes."
)

DEFAULT_CONFIG: Dict = {
    "mongo": {"uri": "mongodb://melissae_mongo:27017", "db": "melissae"},
    "bedrock": {
        "region": "us-east-1",
        "model_id": "anthropic.claude-3-5-sonnet-20240620-v1:0",
        "temperature": 0.2,
        "max_tokens": 2048,
    },
    "inspektor": {"killchain_limit": 200},
}


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

def _deep_merge(base: Dict, override: Dict) -> Dict:
    out = dict(base)
    for key, val in (override or {}).items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def load_config(path: str) -> Dict:
    cfg = DEFAULT_CONFIG
    p = Path(path)
    if p.is_file():
        try:
            with open(p, "r", encoding="utf-8") as f:
                cfg = _deep_merge(cfg, yaml.safe_load(f) or {})
        except (OSError, yaml.YAMLError) as e:
            log.warning("Cannot read config %s (%s), using defaults", path, e)
    else:
        log.info("No config file at %s, using defaults", path)

    cfg["mongo"]["uri"] = os.getenv("MONGO_URI", cfg["mongo"]["uri"])
    cfg["mongo"]["db"] = os.getenv("MONGO_DB", cfg["mongo"]["db"])
    cfg["bedrock"]["region"] = os.getenv(
        "AWS_REGION", os.getenv("AWS_DEFAULT_REGION", cfg["bedrock"]["region"])
    )
    cfg["bedrock"]["model_id"] = os.getenv("BEDROCK_MODEL_ID", cfg["bedrock"]["model_id"])
    return cfg


# --------------------------------------------------------------------------- #
# Prompt assembly from Markdown
# --------------------------------------------------------------------------- #

def _expand_tool_refs(text: str) -> str:
    def repl(match: re.Match) -> str:
        names = [n.strip() for n in match.group(1).split(",") if n.strip()]
        lines = []
        for name in names:
            t = tools.TOOLS_BY_NAME.get(name)
            if t is None:
                lines.append(f"- `{name}`: (unknown tool)")
                continue
            summary = " ".join((t.description or "").split())
            lines.append(f"- `{name}`: {summary}")
        return "\n".join(lines)

    return re.sub(r"\{\{tools:([^}]*)\}\}", repl, text)


def build_system_prompt() -> str:
    system = (BASE_DIR / "prompts" / "system.md").read_text(encoding="utf-8")

    skills_dir = BASE_DIR / "skills"
    blocks: List[str] = []
    if skills_dir.is_dir():
        for skill_file in sorted(skills_dir.glob("*.md")):
            blocks.append(_expand_tool_refs(skill_file.read_text(encoding="utf-8")).strip())
    skills_md = "\n\n---\n\n".join(blocks) if blocks else "(no skills defined)"

    if "{{skills}}" in system:
        return system.replace("{{skills}}", skills_md)
    return f"{system.rstrip()}\n\n{skills_md}"


# --------------------------------------------------------------------------- #
# Agent
# --------------------------------------------------------------------------- #

def build_agent(cfg: Dict) -> AgentExecutor:
    client = boto3.client("bedrock-runtime", region_name=cfg["bedrock"]["region"])
    llm = ChatBedrock(
        client=client,
        model_id=cfg["bedrock"]["model_id"],
        model_kwargs={
            "temperature": cfg["bedrock"].get("temperature", 0.2),
            "max_tokens": cfg["bedrock"].get("max_tokens", 2048),
        },
    )
    prompt = ChatPromptTemplate.from_messages([
        ("system", build_system_prompt()),
        MessagesPlaceholder(variable_name="chat_history", optional=True),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])
    agent = create_tool_calling_agent(llm, tools.TOOLS, prompt)
    return AgentExecutor(agent=agent, tools=tools.TOOLS, max_iterations=15, verbose=False)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def _format_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _verdict_counts(threats: List[Dict]) -> Dict[str, int]:
    counts = {"malicious": 0, "suspicious": 0, "benign": 0}
    for t in threats:
        v = t.get("verdict", "benign")
        counts[v] = counts.get(v, 0) + 1
    return counts


def store_report(db, markdown: str, threats: List[Dict]) -> Dict:
    doc = {
        "_id": "latest",
        "markdown": markdown.strip(),
        "generated_at": _format_utc_iso(datetime.now(timezone.utc)),
        "threats_analyzed": len(threats),
        "counts": _verdict_counts(threats),
        "model": os.getenv("BEDROCK_MODEL_ID", DEFAULT_CONFIG["bedrock"]["model_id"]),
    }
    try:
        db[REPORT_COLLECTION].replace_one({"_id": "latest"}, doc, upsert=True)
    except PyMongoError as e:
        log.error("Could not store Inspektor report: %s", e)
    return {k: v for k, v in doc.items() if k != "_id"}


def _extract_text(result) -> str:
    body = result.get("output", "") if isinstance(result, dict) else str(result)
    if isinstance(body, list):
        body = "".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in body)
    return body


# --------------------------------------------------------------------------- #
# Runtime state
# --------------------------------------------------------------------------- #

app = Flask("inspektor")

_LOCK = threading.Lock()   # serialize LLM calls (one Bedrock conversation at a time)
_STATE: Dict = {"cfg": None, "agent": None, "db": None, "ready": False}


def _history_to_messages(history) -> List:
    """Convert a [{role, content}] chat history into LangChain messages."""
    messages = []
    for turn in history or []:
        if not isinstance(turn, dict):
            continue
        role = (turn.get("role") or "").lower()
        content = (turn.get("content") or "").strip()
        if not content:
            continue
        if role in ("user", "human"):
            messages.append(HumanMessage(content=content))
        elif role in ("assistant", "ai", "inspektor"):
            messages.append(AIMessage(content=content))
    return messages


def generate_report() -> Dict:
    """Run a full threat briefing, store it and return the report document."""
    db = _STATE["db"]
    try:
        threats = list(db["threats"].find({}, {"_id": 0, "verdict": 1}))
    except PyMongoError as e:
        raise RuntimeError(f"Cannot read threats: {e}") from e

    if not threats:
        log.info("No threats to analyze; publishing idle briefing")
        return store_report(db, IDLE_BRIEFING, threats)

    with _LOCK:
        markdown = _extract_text(_STATE["agent"].invoke({"input": KICKOFF}))
    if not markdown.strip():
        raise RuntimeError("Model returned an empty briefing")

    report = store_report(db, markdown, threats)
    log.info("Briefing published (%d threats analyzed)", len(threats))
    return report


# --------------------------------------------------------------------------- #
# HTTP API
# --------------------------------------------------------------------------- #

@app.get("/health")
def health():
    return jsonify({"status": "ok" if _STATE["ready"] else "starting"})


@app.post("/report")
def http_report():
    if not _STATE["ready"]:
        return jsonify({"error": "Inspektor is still starting"}), 503
    try:
        return jsonify(generate_report())
    except Exception as e:  # noqa: BLE001 - surface a clean error to the dashboard
        log.error("Report generation failed: %s", e)
        return jsonify({"error": str(e)}), 502


@app.post("/chat")
def http_chat():
    if not _STATE["ready"]:
        return jsonify({"error": "Inspektor is still starting"}), 503

    payload = request.get_json(silent=True) or {}
    message = (payload.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message is required"}), 400

    history = _history_to_messages(payload.get("history"))
    try:
        with _LOCK:
            result = _STATE["agent"].invoke({"input": message, "chat_history": history})
        reply = _extract_text(result).strip()
        return jsonify({"reply": reply or "(no answer)"})
    except Exception as e:  # noqa: BLE001
        log.error("Chat turn failed: %s", e)
        return jsonify({"error": str(e)}), 502


# --------------------------------------------------------------------------- #
# Startup
# --------------------------------------------------------------------------- #

def init() -> None:
    cfg = load_config(os.getenv("INSPEKTOR_CONFIG", str(BASE_DIR / "config.yml")))
    tools.KILLCHAIN_LIMIT = int(cfg["inspektor"].get("killchain_limit", 200))

    if not (os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")):
        log.warning(
            "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are not set — "
            "Bedrock calls will fail until credentials are provided."
        )

    log.info(
        "Inspektor init | model=%s region=%s",
        cfg["bedrock"]["model_id"], cfg["bedrock"]["region"],
    )

    while True:
        try:
            client = MongoClient(cfg["mongo"]["uri"], serverSelectionTimeoutMS=5000)
            client.admin.command("ping")
            tools.DB = client[cfg["mongo"]["db"]]
            break
        except PyMongoError as e:
            log.warning("MongoDB not ready (%s), retrying in 5s", e)
            time.sleep(5)

    _STATE["cfg"] = cfg
    _STATE["db"] = tools.DB
    _STATE["agent"] = build_agent(cfg)
    _STATE["ready"] = True
    log.info("Inspektor ready — listening for on-demand requests")


def main() -> None:
    init()
    port = int(os.getenv("INSPEKTOR_PORT", "8088"))
    app.run(host="0.0.0.0", port=port, threaded=True)


if __name__ == "__main__":
    main()
