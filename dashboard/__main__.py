"""Serve the dashboard: python -m dashboard [--port 8080]

Binds to 127.0.0.1 only. Uses the standard library HTTP server, so no extra
dependencies are needed.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dashboard.app import Dashboard

STATIC = Path(__file__).resolve().parent / "static"
MAX_BODY = 64 * 1024


def make_handler(app: Dashboard):
    routes_post = {
        "/api/handshake": lambda b: app.handshake(b["client_id"]),
        "/api/request": lambda b: app.request(b["client_id"], b["op"], b.get("params") or {}),
        "/api/replay": lambda b: app.replay_last(b["client_id"]),
        "/api/tamper": lambda b: app.tamper_last(b["client_id"]),
        "/api/clock": lambda b: app.advance_clock(b["advance_ms"]),
        "/api/reset": lambda b: app.reset(),
        "/api/attack": lambda b: app.run_attack(b.get("name")),
        "/api/evaluate": lambda b: app.evaluate(int(b.get("requests", 300)), int(b.get("clients", 4))),
    }
    routes_get = {
        "/api/state": app.state,
        "/api/attacks": app.attack_catalog,
        "/api/evaluation": lambda: app.last_evaluation,
    }

    class Handler(BaseHTTPRequestHandler):
        server_version = "FlowStateDashboard/1.0"

        def log_message(self, fmt, *args):  # keep the console for the gateway story
            pass

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, data) -> None:
            self._send(status, json.dumps(data).encode(), "application/json")

        def _dispatch(self, fn) -> None:
            try:
                self._json(HTTPStatus.OK, fn())
            except (KeyError, ValueError, TypeError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except RuntimeError as exc:
                self._json(HTTPStatus.CONFLICT, {"error": str(exc)})
            except Exception as exc:  # surface server bugs to the page instead of hanging
                traceback.print_exc()
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path in routes_get:
                return self._dispatch(routes_get[path])
            name = "index.html" if path == "/" else path.lstrip("/")
            target = (STATIC / name).resolve()
            if STATIC not in target.parents or not target.is_file():
                return self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            self._send(HTTPStatus.OK, target.read_bytes(), ctype)

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                self.close_connection = True
                return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body too large"})
            # Always consume the body before replying: closing a socket with unread
            # data makes Windows reset the connection instead of delivering the reply.
            raw = self.rfile.read(length)
            if path not in routes_post:
                return self._json(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})
            try:
                body = json.loads(raw or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": "body must be a JSON object"})
            self._dispatch(lambda: routes_post[path](body))

    return Handler


class ExclusiveHTTPServer(ThreadingHTTPServer):
    # The stdlib default (SO_REUSEADDR) lets a second server bind the same port on
    # Windows, so two dashboards would silently share it. Refuse instead.
    allow_reuse_address = False


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="dashboard")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)

    try:
        server = ExclusiveHTTPServer(("127.0.0.1", args.port), None)
    except OSError:
        raise SystemExit(
            f"Port {args.port} is already in use - is the dashboard already running? "
            f"Close it, or start this one with --port {args.port + 1}."
        )
    app = Dashboard()
    server.RequestHandlerClass = make_handler(app)
    print(f"FlowState dashboard: http://localhost:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.close()


if __name__ == "__main__":
    main()
