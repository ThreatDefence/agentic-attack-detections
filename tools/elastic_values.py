"""Make Sigma values match in Elasticsearch the way Sigma means them.

Two gaps between Sigma and Elasticsearch, closed for the ECS pipeline in convert.py (Lucene and ES|QL):

- Regular expressions. Sigma regexes are Python-style searches: unanchored, with ^ and $ anchors and \\d, \\w and
  \\s classes (\\s becomes a space). Elasticsearch (query_string /re/ and ES|QL RLIKE) uses Lucene regexes, which must match the whole
  value and know none of those. lucene_regex() rewrites one into the other, or raises if it cannot do so faithfully.
- Case. Sigma matches strings without regard to case; a keyword field in Elasticsearch does not. Host names are
  case-insensitive by definition and arrive in any case, so values on host name fields become case-folded regexes.
"""
from dataclasses import dataclass

from sigma.processing.transformations.base import ValueTransformation
from sigma.types import SigmaRegularExpression, SigmaRegularExpressionFlag, SigmaString, SpecialChars

# Host name fields after the ECS mapping: their values are matched without regard to case.
HOST_FIELDS = ["dns.question.name", "url.domain", "destination.domain", "source.domain", "server.domain"]

# \s becomes a space: a Lucene regex inside a query string has no way to write a tab or a line break.
CLASS = {"d": "0-9", "w": "A-Za-z0-9_", "s": " "}
NEGATED = {"D": "d", "W": "w", "S": "s"}
# Lucene treats these as operators outside a character class (RegExp.ALL); Python does not.
LUCENE_ONLY = set('"#@&<>~')
SPECIAL = set(".?+*|{}[]()\\") | LUCENE_ONLY
QUANT = set("*+?}")


def _fold(ch):
    return f"[{ch.lower()}{ch.upper()}]" if ch.isalpha() and ch.lower() != ch.upper() else ch


def _fold_class(body):
    """Add the other case of every letter and letter range in a character class body."""
    extra, i = "", 0
    while i < len(body):
        if body[i] == "\\":
            i += 2
            continue
        if i + 2 < len(body) and body[i + 1] == "-" and body[i].isalpha() and body[i + 2].isalpha():
            extra += body[i:i + 3].swapcase()
            i += 3
            continue
        if body[i].isalpha():
            extra += body[i].swapcase()
        i += 1
    return body + extra


def _tokens(regex, ignorecase):
    """Python regex -> tokens (kind, text). Kinds: lit, open, close, alt, quant, start, end."""
    out, i, n = [], 0, len(regex)
    while i < n:
        c = regex[i]
        if c == "\\":
            if i + 1 >= n:
                raise ValueError("trailing backslash")
            e = regex[i + 1]
            if e in CLASS:
                out.append(("lit", f"[{CLASS[e]}]"))
            elif e in NEGATED:
                out.append(("lit", f"[^{CLASS[NEGATED[e]]}]"))
            elif e.isalnum():
                raise ValueError(f"\\{e} has no Lucene equivalent")
            else:
                out.append(("lit", "\\" + e))
            i += 2
        elif c == "[":
            j, body = i + 1, ""
            if j < n and regex[j] == "^":
                body, j = "^", j + 1
            if j < n and regex[j] == "]":
                body, j = body + "\\]", j + 1
            while j < n and regex[j] != "]":
                if regex[j] == "\\" and j + 1 < n:
                    e = regex[j + 1]
                    if e in CLASS:
                        body += CLASS[e]
                    elif e.isalnum():
                        raise ValueError(f"\\{e} in a character class has no Lucene equivalent")
                    else:
                        body += "\\" + e
                    j += 2
                else:
                    body += regex[j]
                    j += 1
            if j >= n:
                raise ValueError("unterminated character class")
            out.append(("lit", "[" + (_fold_class(body) if ignorecase else body) + "]"))
            i = j + 1
        elif c == "(":
            if regex.startswith("(?:", i):
                i += 3
            elif regex.startswith("(?", i):
                raise ValueError("only (?:...) groups have a Lucene equivalent")
            else:
                i += 1
            out.append(("open", "("))
        elif c == ")":
            out.append(("close", ")"))
            i += 1
        elif c == "|":
            out.append(("alt", "|"))
            i += 1
        elif c == "^":
            out.append(("start", ""))
            i += 1
        elif c == "$":
            out.append(("end", ""))
            i += 1
        elif c in "*+?":
            if c == "?" and out and out[-1][0] == "quant":
                i += 1  # lazy quantifier: the same matches when the whole value must match
                continue
            out.append(("quant", c))
            i += 1
        elif c == "{":
            j = regex.find("}", i)
            if j < 0:
                raise ValueError("unterminated {")
            out.append(("quant", regex[i:j + 1]))
            i = j + 1
        elif c in LUCENE_ONLY:
            out.append(("lit", "\\" + c))
            i += 1
        else:
            out.append(("lit", _fold(c) if ignorecase else c))
            i += 1
    return out


def _split(tokens):
    """Split a token list at its top-level alternations."""
    parts, cur, depth = [], [], 0
    for t in tokens:
        if t[0] == "alt" and depth == 0:
            parts.append(cur)
            cur = []
            continue
        depth += {"open": 1, "close": -1}.get(t[0], 0)
        cur.append(t)
    parts.append(cur)
    return parts


def _group_end(tokens, start):
    depth = 0
    for k in range(start, len(tokens)):
        depth += {"open": 1, "close": -1}.get(tokens[k][0], 0)
        if depth == 0:
            return k
    raise ValueError("unbalanced parentheses")


def _anchor(alt, at_start):
    """Anchor one alternative at one end. Returns the alternative without that anchor, padded with .* if unanchored."""
    pad = [("lit", ".*")]
    if not alt:
        return pad
    edge, kind = (alt[0], "start") if at_start else (alt[-1], "end")
    if edge[0] == kind:
        return alt[1:] if at_start else alt[:-1]
    # (^|X)... at the start or ...(X|$) at the end: the anchor is one way through the group, X the other.
    if at_start and edge[0] == "open":
        end = _group_end(alt, 0)
        inner = _split(alt[1:end])
        rest = alt[end + 1:]
        if [(kind, "")] in inner and not (rest and rest[0][0] == "quant"):
            others = [o for o in inner if o != [(kind, "")]]
            group = [("open", "(")] + pad + [("open", "(")] + _join(others) + [("close", ")"), ("close", ")"), ("quant", "?")]
            return group + rest
    if not at_start and edge[0] == "close":
        depth, begin = 0, None
        for k in range(len(alt) - 1, -1, -1):
            depth += {"close": 1, "open": -1}.get(alt[k][0], 0)
            if depth == 0:
                begin = k
                break
        inner = _split(alt[begin + 1:-1])
        if [(kind, "")] in inner:
            others = [o for o in inner if o != [(kind, "")]]
            group = [("open", "("), ("open", "(")] + _join(others) + [("close", ")")] + pad + [("close", ")"), ("quant", "?")]
            return alt[:begin] + group
    return pad + alt if at_start else alt + pad


def _join(parts):
    out = []
    for k, p in enumerate(parts):
        if k:
            out.append(("alt", "|"))
        out.extend(p)
    return out


def lucene_regex(regex, ignorecase=False):
    """A Python-style regex search -> a Lucene regex for the whole value. Raises ValueError if there is none."""
    parts = []
    for alt in _split(_tokens(regex, ignorecase)):
        alt = _anchor(_anchor(alt, True), False)
        if any(t[0] in ("start", "end") for t in alt):
            raise ValueError(f"an anchor inside {regex!r} has no Lucene equivalent")
        parts.append(alt)
    return "".join(t[1] for t in _join(parts))


def folded_regex(value):
    """A Sigma string (with wildcards) -> a Lucene regex that matches it without regard to case."""
    out = ""
    for part in value.s:
        if part == SpecialChars.WILDCARD_MULTI:
            out += ".*"
        elif part == SpecialChars.WILDCARD_SINGLE:
            out += "."
        else:
            for ch in part:
                out += "\\" + ch if ch in SPECIAL else _fold(ch)
    return out


@dataclass
class LuceneRegexTransformation(ValueTransformation):
    """Rewrite Sigma regexes into Lucene regexes that match the whole value."""

    def apply_value(self, field: str, val: SigmaRegularExpression):
        ignorecase = SigmaRegularExpressionFlag.IGNORECASE in val.flags
        if val.flags - {SigmaRegularExpressionFlag.IGNORECASE}:
            raise ValueError(f"regex flags {val.flags} on {field} have no Lucene equivalent")
        return SigmaRegularExpression(lucene_regex(str(val.regexp), ignorecase))


@dataclass
class CaseFoldTransformation(ValueTransformation):
    """Match plain string values without regard to case, as case-folded Lucene regexes."""

    def apply_value(self, field: str, val: SigmaString):
        return SigmaRegularExpression(folded_regex(val))
