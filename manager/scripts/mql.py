import re
from typing import Dict, Iterable, List, Optional, Tuple

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


def _unquote(s: str) -> str:
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


_FIELD_TERM_RE = re.compile(r'^([A-Za-z_][\w-]*):(.*)$', re.DOTALL)


# Match a single field:value or bareword term
def _match_simple_term(log: Dict, term: str) -> bool:
    term = term.strip()
    if not term:
        return False

    m = _FIELD_TERM_RE.match(term)
    if m:
        field = m.group(1).lower()
        value = _unquote(m.group(2)).lower()
        if not value:
            return False
        if field == "hour":
            return _match_hour(log.get("hour", ""), value)
        getter = _FIELD_GETTERS.get(field)
        if getter is None:
            return False
        return value in str(getter(log) or "").lower()

    needle = _unquote(term).lower()
    if not needle:
        return False
    return any(needle in str(v or "").lower() for v in log.values())


# Tokenizer
_TOKEN_RE = re.compile(
    r'\(|\)|\bAND\b|\bOR\b|\bNOT\b|!|[^\s():"]+:"[^"]*"|"[^"]*"|[^\s()]+',
    re.IGNORECASE,
)

_KEYWORDS = {"AND", "OR", "NOT"}


def _tokenize(query: str) -> List[str]:
    return [m.group(0) for m in _TOKEN_RE.finditer(query)]


class _Parser:
    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _peek_upper(self) -> Optional[str]:
        tok = self._peek()
        return tok.upper() if tok is not None else None

    def _consume(self) -> Optional[str]:
        if self.pos < len(self.tokens):
            tok = self.tokens[self.pos]
            self.pos += 1
            return tok
        return None

    def parse_or(self) -> Tuple:
        left = self.parse_and()
        while self._peek_upper() == "OR":
            self._consume()
            right = self.parse_and()
            left = ("OR", left, right)
        return left

    def parse_and(self) -> Tuple:
        left = self.parse_factor()
        while True:
            nxt = self._peek_upper()
            if nxt is None or nxt == ")" or nxt == "OR":
                break
            if nxt == "AND":
                self._consume()
            # else implicit AND between adjacent factors
            right = self.parse_factor()
            left = ("AND", left, right)
        return left

    def parse_factor(self) -> Tuple:
        tok = self._peek()
        if tok is None:
            return ("TRUE",)
        upper = tok.upper()
        if upper == "NOT" or tok == "!":
            self._consume()
            inner = self.parse_factor()
            return ("NOT", inner)
        if tok == "(":
            self._consume()
            inner = self.parse_or()
            if self._peek() == ")":
                self._consume()
            return inner
        if upper in _KEYWORDS or tok == ")":
            self._consume()
            return ("TRUE",)
        self._consume()
        return ("TERM", tok)


def _eval(node: Tuple, log: Dict) -> bool:
    op = node[0]
    if op == "TRUE":
        return True
    if op == "TERM":
        return _match_simple_term(log, node[1])
    if op == "NOT":
        return not _eval(node[1], log)
    if op == "AND":
        return _eval(node[1], log) and _eval(node[2], log)
    if op == "OR":
        return _eval(node[1], log) or _eval(node[2], log)
    return False


# Return True if a single log entry satisfies the MQL query
def match_log(log: Dict, query: str) -> bool:
    if not query or not query.strip():
        return True
    tokens = _tokenize(query)
    if not tokens:
        return True
    parser = _Parser(tokens)
    tree = parser.parse_or()
    return _eval(tree, log)


# Return logs matching the MQL query
def filter_logs(logs: Iterable[Dict], query: str) -> List[Dict]:
    if not query or not query.strip():
        return list(logs)
    return [log for log in logs if match_log(log, query)]
