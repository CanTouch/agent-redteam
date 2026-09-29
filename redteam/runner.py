"""Load targets and attacks, send each attack to an allowlisted target, store the raw reply."""
import ipaddress
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
MIN_INTERVAL = 2.0  # seconds between requests to a target (hard requirement)


class SafetyError(Exception):
    pass


def load_env(path=ROOT / ".env"):
    """Minimal KEY=VALUE parser. Existing environment variables win."""
    path = Path(path)
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.removeprefix("export ").strip()
        os.environ.setdefault(key, value.strip().strip("'\""))


def load_targets(path=ROOT / "targets.yaml"):
    """Return {name: target}. Every target must carry url and a body_template using {{message}}."""
    data = yaml.safe_load(Path(path).read_text()) or {}
    targets = {}
    for t in data.get("targets") or []:
        for field in ("name", "url", "body_template"):
            if field not in t:
                raise ValueError(f"target missing '{field}': {t}")
        if "{{message}}" not in yaml.safe_dump(t["body_template"]):
            raise ValueError(f"target {t['name']}: body_template must contain {{{{message}}}}")
        if urlparse(t["url"]).scheme not in ("http", "https"):
            raise ValueError(f"target {t['name']}: url must be http(s)")
        t.setdefault("method", "POST")
        t.setdefault("headers", {})
        t.setdefault("response_path", "")
        t.setdefault("canaries", [])
        targets[t["name"]] = t
    return targets


def load_attacks(directory=ROOT / "attacks", category=None):
    attacks = []
    for f in sorted(Path(directory).glob("*.yaml")):
        for a in (yaml.safe_load(f.read_text()) or {}).get("attacks") or []:
            a = dict(a)
            a["message"] = str(a.get("message") or "") * int(a.pop("repeat", 1))
            attacks.append(a)
    if category:
        attacks = [a for a in attacks if a["category"] == category]
    return attacks


def expand_env(value):
    """Replace ${VAR} with the environment value so header secrets stay in .env."""
    def sub(m):
        if m.group(1) not in os.environ:
            raise SafetyError(f"environment variable {m.group(1)} is not set (add it to .env)")
        return os.environ[m.group(1)]
    return re.sub(r"\$\{(\w+)\}", sub, str(value))


def fill_template(node, message):
    if isinstance(node, dict):
        return {k: fill_template(v, message) for k, v in node.items()}
    if isinstance(node, list):
        return [fill_template(v, message) for v in node]
    if isinstance(node, str):
        return node.replace("{{message}}", message)
    return node


def extract(data, path):
    """Dotted path lookup; numeric segments index lists (n8n often returns [{"output": ...}])."""
    if not path:
        return data
    for seg in str(path).split("."):
        if isinstance(data, list) and seg.lstrip("-").isdigit() and -len(data) <= int(seg) < len(data):
            data = data[int(seg)]
        elif isinstance(data, dict) and seg in data:
            data = data[seg]
        else:
            return None
    return data


def is_loopback(url):
    host = urlparse(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class RateLimiter:
    def __init__(self, interval, clock=time.monotonic, sleep=time.sleep):
        self.interval, self.clock, self.sleep = interval, clock, sleep
        self.last = None

    def wait(self):
        if self.last is not None:
            remaining = self.last + self.interval - self.clock()
            if remaining > 0:
                self.sleep(remaining)
        self.last = self.clock()


class Runner:
    def __init__(self, target, allowlist, interval=MIN_INTERVAL, timeout=60, session=None):
        self.allowlist = set(allowlist)
        self._check(target["url"])
        if interval < MIN_INTERVAL and not is_loopback(target["url"]):
            raise SafetyError(f"rate limit below {MIN_INTERVAL}s is only allowed for loopback targets")
        self.target = target
        self.limiter = RateLimiter(interval)
        self.timeout = timeout
        self.session = session or requests.Session()

    def _check(self, url):
        if url not in self.allowlist:
            raise SafetyError(f"refusing to send to {url}: not listed in targets.yaml")

    def send(self, message):
        t = self.target
        self._check(t["url"])  # re-checked on every request
        headers = {k: expand_env(v) for k, v in t["headers"].items()}
        payload = fill_template(t["body_template"], message)
        self.limiter.wait()
        result = {"status": None, "latency_ms": None, "raw": None, "reply": None, "error": None}
        start = time.monotonic()
        try:
            # never follow redirects: the new location is not on the allowlist
            if t["method"].upper() == "GET":
                r = self.session.get(t["url"], params=payload, headers=headers, timeout=self.timeout,
                                     allow_redirects=False)
            else:
                r = self.session.request(t["method"].upper(), t["url"], json=payload, headers=headers,
                                         timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as e:
            result["error"] = f"{type(e).__name__}: {e}"
            return result
        result["latency_ms"] = round((time.monotonic() - start) * 1000)
        result["status"] = r.status_code
        result["raw"] = r.text
        if 300 <= r.status_code < 400:
            result["error"] = f"redirect to {r.headers.get('Location')} not followed (not in targets.yaml)"
            return result
        try:
            reply = extract(r.json(), t["response_path"])
        except ValueError:
            reply = None
        if reply is None:
            reply = r.text  # path did not resolve: judge the raw body
        result["reply"] = reply if isinstance(reply, str) else yaml.safe_dump(reply, allow_unicode=True)
        return result


def run(runner, attacks, judge_fn, progress=None):
    """Send every attack, judge the reply, return result rows."""
    results = []
    for i, attack in enumerate(attacks, 1):
        sent = runner.send(attack["message"])
        verdict = judge_fn(attack, sent)
        row = {**{k: attack.get(k) for k in ("id", "category", "severity", "message", "success_if")},
               **sent, **verdict}
        results.append(row)
        if progress:
            progress(i, len(attacks), row)
    return results
