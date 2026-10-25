"""Infrastructure intelligence: typosquat/lookalike domains and suspicious sender checks."""

from __future__ import annotations

import socket
import unicodedata

KEYBOARD_NEIGHBOURS = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr", "f": "drtgvc", "g": "ftyhbv",
    "h": "gyujnb", "i": "ujko", "j": "huikmn", "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm",
    "o": "iklp", "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy", "u": "yhji", "v": "cfgb",
    "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
}
HOMOGLYPHS = {
    "o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5"], "g": ["9", "q"],
    "m": ["rn"], "w": ["vv"], "d": ["cl"],
}
CONFUSABLE_TO_ASCII = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "rn": "m", "vv": "w", "cl": "d"}
ALT_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "us", "app", "online", "site", "xyz"]


def split_domain(domain: str) -> tuple[str, str]:
    domain = domain.strip().lower().rstrip(".")
    if "." not in domain:
        raise ValueError(f"not a domain: {domain!r}")
    label, _, tld = domain.partition(".")
    return label, tld


def lookalikes(domain: str) -> dict[str, str]:
    """Generate candidate lookalike domains mapped to the technique that produced them."""
    label, tld = split_domain(domain)
    out: dict[str, str] = {}

    def add(lbl: str, t: str, technique: str):
        if lbl and lbl != label or t != tld:
            if lbl and all(c.isalnum() or c == "-" for c in lbl) and not lbl.startswith("-"):
                out.setdefault(f"{lbl}.{t}", technique)

    for i in range(len(label)):
        add(label[:i] + label[i + 1:], tld, "omission")
        add(label[:i] + label[i] + label[i:], tld, "repetition")
        if i < len(label) - 1:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:], tld, "transposition")
        for n in KEYBOARD_NEIGHBOURS.get(label[i], ""):
            add(label[:i] + n + label[i + 1:], tld, "keyboard_replacement")
        for h in HOMOGLYPHS.get(label[i], []):
            add(label[:i] + h + label[i + 1:], tld, "homoglyph")
        if 0 < i:
            add(label[:i] + "-" + label[i:], tld, "hyphenation")
    for t in ALT_TLDS:
        add(label, t, "tld_swap")
    for affix in ("secure", "login", "support", "account", "verify", "my"):
        add(f"{label}-{affix}", tld, "affix")
        add(f"{affix}-{label}", tld, "affix")
    out.pop(domain.lower(), None)
    return out


def resolves(domain: str, timeout: float = 3.0) -> bool:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        socket.getaddrinfo(domain, None)
        return True
    except (socket.gaierror, UnicodeError, OSError):
        return False
    finally:
        socket.setdefaulttimeout(old)


def skeleton(label: str) -> str:
    """Collapse visually confusable characters so lookalikes compare equal to the original."""
    s = unicodedata.normalize("NFKD", label.lower())
    s = "".join(c for c in s if not unicodedata.combining(c))
    for k in sorted(CONFUSABLE_TO_ASCII, key=len, reverse=True):
        s = s.replace(k, CONFUSABLE_TO_ASCII[k])
    return s.replace("-", "")


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def check_sender(address: str, trusted_domains: list[str]) -> dict:
    """Flag a sender whose domain imitates one of the trusted domains (e.g. invoice fraud)."""
    domain = address.rsplit("@", 1)[-1].strip().lower()
    try:
        domain = domain.encode("idna").decode() if not domain.startswith("xn--") else domain
    except UnicodeError:
        pass
    result = {"address": address, "domain": domain, "verdict": "unknown", "imitates": None, "reasons": []}
    for trusted in trusted_domains:
        trusted = trusted.lower()
        if domain == trusted or domain.endswith("." + trusted):
            return {**result, "verdict": "trusted", "imitates": trusted}
    sender_label, sender_tld = split_domain(domain) if "." in domain else (domain, "")
    for trusted in trusted_domains:
        t_label, t_tld = split_domain(trusted)
        reasons = []
        if domain.startswith("xn--"):
            reasons.append("internationalised (punycode) domain")
        if skeleton(sender_label) == skeleton(t_label) and sender_label != t_label:
            reasons.append("visually confusable with trusted domain")
        dist = levenshtein(sender_label, t_label)
        if 0 < dist <= 2 and len(t_label) > 3:
            reasons.append(f"edit distance {dist} from {t_label}")
        if sender_label == t_label and sender_tld != t_tld:
            reasons.append(f"same name, different TLD (.{sender_tld} vs .{t_tld})")
        if t_label in sender_label and sender_label != t_label:
            reasons.append(f"contains trusted name '{t_label}'")
        if reasons:
            return {**result, "verdict": "suspicious", "imitates": trusted, "reasons": reasons}
    return result
