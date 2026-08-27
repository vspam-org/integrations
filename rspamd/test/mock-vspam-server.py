#!/usr/bin/env python3
"""Mock vspam-agent and public API, so the Rspamd module can be exercised
without touching the real service.

Serves both contracts on one port and dispatches by path:

  POST /check                       the agent's HTTP check API (port 10046)
  GET  /api/v1/public/lookup/<hash> the public hash lookup used as fallback
  GET  /api/v1/lookup/<hash>        the authenticated variant
  GET  /health                      the agent's health endpoint

The response shapes are copied from agent/internal/httpcheck/server.go and
agent/internal/checker/api_client.go. If either of those changes, this mock
and the module both need to follow.
"""

import hashlib
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

# One fixture per category the module folds indicators into, plus a
# not-listed-but-scored one, which is the case a DNSBL cannot express.
FIXTURES = {
    "phish.example.net": {
        "category": "phishing_url",
        "listed": True,
        "source": "consensus",
    },
    "malware.example.net": {
        "category": "malware_domain",
        "listed": True,
        "source": "consensus",
    },
    "botnet.example.net": {
        "category": "botnet_c2",
        "listed": True,
        "source": "consensus",
    },
    "spammy.example.net": {
        "category": "spam_source",
        "listed": True,
        "source": "consensus",
    },
    "tornode.example.net": {
        "category": "tor_exit_node",
        "listed": True,
        "source": "consensus",
    },
    # Deliberately a category the module does not know, to prove an
    # unrecognised listing still scores as a threat rather than vanishing.
    "unknowncat.example.net": {
        "category": "some_future_category",
        "listed": True,
        "source": "consensus",
    },
    "maybe.example.net": {
        "category": "credential_harvest",
        "listed": False,
        "verdict": "suspicious",
        "source": "shadow_v2",
        "needs_manual_review": True,
        "reason_summary": "Sparse-history domain with phishing-like login patterns",
    },
    # A listed IP, to cover the client_ip path.
    "203.0.113.66": {
        "category": "blacklist_ip",
        "listed": True,
        "source": "consensus",
    },
}


def normalize(value):
    """Mirror the agent's hashIOC normalisation for the values we ship."""
    return value.strip().lower().rstrip(".")


HASHES = {
    hashlib.sha256(normalize(k).encode()).hexdigest(): k for k in FIXTURES
}


def host_of(url):
    parts = urlsplit(url if "//" in url else "//" + url)
    host = parts.hostname or ""
    return normalize(host)


def agent_response(name, fx):
    """The shape agent/internal/httpcheck returns for one decision."""
    if fx["listed"]:
        return {
            "malicious": True,
            "action": "reject",
            "reason": "vspam.org: " + fx["category"],
            "category": fx["category"],
            "already_known": True,
            "ioc_type": "domain",
            "ioc_value": name,
            "lookup_value": name,
            "effective_decision": {
                "source": fx["source"],
                "verdict": "malicious",
                "listed": True,
                "rationale": "Published to the blocklist by community consensus.",
            },
        }
    return {
        "malicious": False,
        "action": "allow",
        "reason": "vspam.org: " + fx.get("reason_summary", ""),
        "category": fx["category"],
        "already_known": True,
        "ioc_type": "domain",
        "ioc_value": name,
        "lookup_value": name,
        "effective_decision": {
            "source": fx["source"],
            "verdict": fx.get("verdict", "benign"),
            "listed": False,
            "rationale": "Shadow scoring keeps this out of block feeds until review completes.",
        },
        "scoring": {
            "score": "61.0000",
            "confidence": "0.4100",
            "needs_manual_review": fx.get("needs_manual_review", False),
            "reason_summary": fx.get("reason_summary", ""),
        },
    }


def api_response(name, fx):
    """The {"data": ...} envelope of GET /api/v1/public/lookup/<hash>."""
    data = {
        "status": "confirmed" if fx["listed"] else "under_review",
        "confidence": "0.9100",
        "ioc_type": "domain",
        "category": fx["category"],
        "effective_decision": {
            "source": fx["source"],
            "verdict": "malicious" if fx["listed"] else fx.get("verdict", "benign"),
            "listed": fx["listed"],
            "rationale": "Fixture.",
        },
    }
    if not fx["listed"]:
        data["scoring"] = {
            "source": fx["source"],
            "verdict": fx.get("verdict", "benign"),
            "score": "61.0000",
            "confidence": "0.4100",
            "needs_manual_review": fx.get("needs_manual_review", False),
            "reason_summary": fx.get("reason_summary", ""),
        }
    return {"data": data}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("mock: " + (fmt % args) + "\n")

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path

        if path == "/health":
            self._send(200, {"status": "ok"})
            return

        for prefix in ("/api/v1/public/lookup/", "/api/v1/lookup/"):
            if path.startswith(prefix):
                digest = path[len(prefix):]
                name = HASHES.get(digest)
                if not name:
                    self._send(404, {"error": "not found"})
                    return
                self._send(200, api_response(name, FIXTURES[name]))
                return

        self._send(404, {"error": "not found"})

    def do_POST(self):
        if urlsplit(self.path).path != "/check":
            self._send(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._send(400, {"error": "invalid JSON body"})
            return

        # Same order the agent walks: sender domain, client IP, then URLs.
        candidates = []
        if req.get("sender_domain"):
            candidates.append(normalize(req["sender_domain"]))
        if req.get("client_ip"):
            candidates.append(normalize(req["client_ip"]))
        candidates.extend(host_of(u) for u in req.get("urls") or [])

        if not req.get("sender_domain") and not req.get("urls"):
            self._send(400, {"error": "sender_domain or urls required"})
            return

        best = None
        for name in candidates:
            fx = FIXTURES.get(name)
            if not fx:
                continue
            if fx["listed"]:
                self._send(200, agent_response(name, fx))
                return
            if best is None:
                best = (name, fx)

        if best:
            self._send(200, agent_response(*best))
            return

        self._send(200, {"malicious": False, "action": "allow"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 10046
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
