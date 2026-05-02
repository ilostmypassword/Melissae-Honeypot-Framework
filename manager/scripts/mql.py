import re
from typing import Dict, Iterable, List, Tuple

_FIELD_GETTERS = {
    "protocol":   lambda log: log.get("protocol", ""),
    "action":     lambda log: log.get("action", ""),
    "ip":         lambda log: log.get("ip", ""),
    "date":       lambda log: log.get("date", ""),
    "user":       lambda log: log.get("user", ""),
    "user-agent": lambda log: log.get("user-agent", ""),
    "path":       lambda log: log.get("path", ""),
    "cve":        lambda log: log.get("cve", ""),
    "agent":      lambda log: log.get("agent_id", ""),
    "agent_id":   lambda log: log.get("agent_id", ""),
}


def _match_hour(log_hour: str, search_value: str) -> bool:
    if not log_hour:
        return False
    log_h = log_hour.lower().split(":")[0]
    search_h = search_value.lower().split(":")[0]
    return log_h == search_h


def _match_term(log: Dict, term: str) -> bool:
    term = term.strip()
    if not term:
        return False

    negation = False
    m = re.match(r"^(NOT\s+|!)", term, re.IGNORECASE)
    if m:
        negation = True
        term = term[m.end():].strip()

    if ":" in term:
        field, _, value = term.partition(":")
        field = field.strip().lower()
        value = value.strip().lower()
        if not value:
            return False if not negation else True

        if field == "hour":
            matched = _match_hour(log.get("hour", ""), value)
        else:
            getter = _FIELD_GETTERS.get(field)
            if getter is None:
                matched = False
            else:
                matched = value in str(getter(log) or "").lower()
    else:
        needle = term.lower()
        matched = any(needle in str(v or "").lower() for v in log.values())

    return (not matched) if negation else matched


_OPERATOR_RE = re.compile(r"(\bAND\b|\bOR\b)", re.IGNORECASE)


def _parse_groups(query: str) -> List[Tuple[str, List[str]]]:
    """Split query on AND/OR. Returns list of (operator_to_combine_with_previous, terms)."""
    parts = _OPERATOR_RE.split(query)
    groups: List[Tuple[str, List[str]]] = []
    current: List[str] = []
    last_op = "AND"

    for part in parts:
        chunk = part.strip()
        if not chunk:
            continue
        upper = chunk.upper()
        if upper == "AND":
            if current:
                groups.append((last_op, current))
                current = []
            last_op = "AND"
        elif upper == "OR":
            if current:
                groups.append((last_op, current))
                current = []
            last_op = "OR"
        else:
            if len(chunk) >= 2:
                if ":" in chunk and chunk.split(":", 1)[1].strip() == "":
                    continue
                current.append(chunk)

    if current:
        groups.append((last_op, current))
    return groups


def match_log(log: Dict, query: str) -> bool:
    """Return True if a single log entry satisfies the MQL query."""
    if not query or not query.strip():
        return True
    groups = _parse_groups(query)
    if not groups:
        return False

    accumulator = None  # bool result so far
    for idx, (op, terms) in enumerate(groups):
        group_match = all(_match_term(log, t) for t in terms)
        if idx == 0:
            accumulator = group_match
        elif op == "AND":
            accumulator = accumulator and group_match
        else:  # OR
            accumulator = accumulator or group_match
    return bool(accumulator)


def filter_logs(logs: Iterable[Dict], query: str) -> List[Dict]:
    """Return logs matching the MQL query."""
    if not query or not query.strip():
        return list(logs)
    return [log for log in logs if match_log(log, query)]
