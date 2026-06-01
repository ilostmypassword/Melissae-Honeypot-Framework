#!/usr/bin/env python3

from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import yaml
import boto3
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_aws import ChatBedrock
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from pymongo import MongoClient
from pymongo.errors import PyMongoError

import tools

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("inspector")

BASE_DIR = Path(__file__).resolve().parent
REPORT_COLLECTION = "inspector_report"

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
    "inspector": {"poll_interval_seconds": 300, "killchain_limit": 200},
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


def store_report(db, markdown: str, threats: List[Dict]) -> None:
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
        log.error("Could not store Inspector report: %s", e)


def _extract_text(result) -> str:
    body = result.get("output", "") if isinstance(result, dict) else str(result)
    if isinstance(body, list):
        body = "".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in body)
    return body


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #

def run_cycle(db, agent: AgentExecutor) -> None:
    try:
        threats = list(db["threats"].find({}, {"_id": 0, "verdict": 1}))
    except PyMongoError as e:
        log.error("Cannot read threats: %s", e)
        return

    if not threats:
        store_report(db, IDLE_BRIEFING, threats)
        log.info("No threats to analyze; published idle briefing")
        return

    try:
        markdown = _extract_text(agent.invoke({"input": KICKOFF}))
        if not markdown.strip():
            log.warning("Empty briefing from model, keeping previous report")
            return
        store_report(db, markdown, threats)
        log.info("Briefing published (%d threats analyzed)", len(threats))
    except Exception as e:
        log.error("Failed to generate briefing: %s", e)


def main() -> None:
    cfg = load_config(os.getenv("INSPECTOR_CONFIG", str(BASE_DIR / "config.yml")))

    tools.KILLCHAIN_LIMIT = int(cfg["inspector"].get("killchain_limit", 200))
    interval = int(cfg["inspector"].get("poll_interval_seconds", 300))

    if not (os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")):
        log.warning(
            "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are not set — "
            "Bedrock calls will fail until credentials are provided."
        )

    log.info(
        "Inspector starting | model=%s region=%s interval=%ss",
        cfg["bedrock"]["model_id"], cfg["bedrock"]["region"], interval,
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

    agent = build_agent(cfg)

    while True:
        try:
            run_cycle(tools.DB, agent)
        except Exception as e:
            log.error("Unexpected error in cycle: %s", e)
        time.sleep(interval)


if __name__ == "__main__":
    main()
