#!/usr/bin/env python3

from __future__ import annotations

import argparse
import configparser
import functools
import json
import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from flask import Flask, Response, abort, jsonify, request, send_file, send_from_directory

from matrix_redaction_logger import extract_media_refs, load_config

try:
    from nio.crypto.attachments import decrypt_attachment
except ImportError:
    decrypt_attachment = None

# config
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_FILE = BASE_DIR / "templates" / "index.html"
BOOTSTRAP_FILE = "bootstrap.min.css"
BOOTSTRAP_URL = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css"

OWN_USER_ROLES = ("redacter", "sender", "any")

ROOM_EVENT_TYPES = ("m.room.member",)

# configparser
def load_web_config(path: str) -> dict[str, Any]:
    ini = configparser.ConfigParser(interpolation=None)
    ini.read(path, encoding="utf-8")
    sec = ini["web"] if ini.has_section("web") else None
    get = (lambda k, d: sec.get(k, d)) if sec is not None else (lambda k, d: d)
    own_role = str(get("own_user_role", "redacter")).strip().lower()
    if own_role not in OWN_USER_ROLES:
        own_role = "redacter"
    return {
        "host": str(get("host", "127.0.0.1")).strip(),
        "port": int(get("port", "8080")),
        "context_limit": int(get("context_limit", "30")),
        "own_user": str(get("own_user", "")).strip(),
        "own_user_role": own_role,
    }


def ensure_bootstrap() -> None:
    target = STATIC_DIR / BOOTSTRAP_FILE
    if target.exists():
        return
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    print(f"{BOOTSTRAP_FILE} missing - downloading from {BOOTSTRAP_URL} …")
    try:
        r = requests.get(BOOTSTRAP_URL, timeout=30)
        r.raise_for_status()
        target.write_bytes(r.content)
        print(f"saved as {target}")
    except Exception as e:
        print(f"WARNING: bootstrap download failed: ({e}). "
              f"please download bootstrap.min.css into {STATIC_DIR}.")


def homeserver_of(user_id: str | None) -> str:
    if not user_id or ":" not in user_id:
        return ""
    return user_id.split(":", 1)[1]


def sql_homeserver(column: str) -> str:
    return f"substr({column}, instr({column}, ':') + 1)"


class MatrixError(Exception):
    def __init__(self, status: int, errcode: str, message: str) -> None:
        super().__init__(message)
        self.status, self.errcode, self.message = status, errcode, message


class Matrix:
    LAZY_FILTER = json.dumps({"lazy_load_members": True})

    def __init__(self, homeserver: str, token: str, max_bytes: int) -> None:
        self.hs = homeserver.rstrip("/")
        self.max_bytes = max_bytes
        self.s = requests.Session()
        self.s.headers["Authorization"] = f"Bearer {token}"

    @staticmethod
    def _check(r: requests.Response) -> dict[str, Any]:
        if r.status_code >= 400:
            try:
                j = r.json()
            except ValueError:
                j = {}
            raise MatrixError(r.status_code, j.get("errcode", ""), j.get("error") or f"HTTP {r.status_code}")
        return r.json()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._check(self.s.get(self.hs + path, params=params, timeout=30))

    def _post(self, path: str, body: dict[str, Any], params: Any = None) -> dict[str, Any]:
        return self._check(self.s.post(self.hs + path, json=body, params=params, timeout=60))

    @staticmethod
    def _q(v: str) -> str:
        return quote(v, safe="")

    def whoami(self) -> str:
        return self._get("/_matrix/client/v3/account/whoami").get("user_id", "")

    def joined_rooms(self) -> list[str]:
        return self._get("/_matrix/client/v3/joined_rooms").get("joined_rooms", [])

    def state_event(self, room_id: str, event_type: str, state_key: str = "") -> dict[str, Any] | None:
        try:
            return self._get(f"/_matrix/client/v3/rooms/{self._q(room_id)}/state/{self._q(event_type)}/"
                             f"{self._q(state_key)}")
        except MatrixError:
            return None

    def join(self, room: str, via: list[str]) -> str:
        params = [("server_name", s) for s in via] or None
        return self._post(f"/_matrix/client/v3/join/{self._q(room)}", {}, params).get("room_id", "")

    def leave(self, room_id: str) -> None:
        self._post(f"/_matrix/client/v3/rooms/{self._q(room_id)}/leave", {})

    def context(self, room_id: str, event_id: str, limit: int) -> dict[str, Any]:
        return self._get(f"/_matrix/client/v3/rooms/{self._q(room_id)}/context/{self._q(event_id)}",
                         {"limit": limit, "filter": self.LAZY_FILTER})

    def messages(self, room_id: str, token: str, direction: str, limit: int) -> dict[str, Any]:
        return self._get(f"/_matrix/client/v3/rooms/{self._q(room_id)}/messages",
                         {"from": token, "dir": direction, "limit": limit, "filter": self.LAZY_FILTER})

    def event(self, room_id: str, event_id: str) -> dict[str, Any]:
        return self._get(f"/_matrix/client/v3/rooms/{self._q(room_id)}/event/{self._q(event_id)}")

    def download(self, mxc: str) -> tuple[bytes, str | None]:
        m = re.match(r"^mxc://([^/]+)/([^/?#]+)", mxc)
        if not m:
            raise ValueError("invalid mxc url")
        server, media_id = m.groups()
        last = ""
        for path in (f"/_matrix/client/v1/media/download/{server}/{media_id}",
                     f"/_matrix/media/v3/download/{server}/{media_id}"):
            r = self.s.get(self.hs + path, params={"allow_redirect": "true"}, stream=True, timeout=60)
            if r.status_code != 200:
                last = f"HTTP {r.status_code}"
                r.close()
                continue
            buf = bytearray()
            for chunk in r.iter_content(65536):
                buf.extend(chunk)
                if len(buf) > self.max_bytes:
                    r.close()
                    raise ValueError("file too large")
            return bytes(buf), r.headers.get("Content-Type")
        raise RuntimeError(f"download failed: {last}")


def create_app(config_path: str) -> Flask:
    cfg = load_config(config_path)
    web = load_web_config(config_path)
    data_dir = Path(cfg["data_dir"]).expanduser().resolve()
    db_path = data_dir / "redaction_logger.db"
    creds_path = data_dir / "credentials.json"

    token = cfg.get("access_token") or ""
    if creds_path.exists():
        token = json.loads(creds_path.read_text()).get("access_token") or token
    if not token:
        raise SystemExit("No Access-Token found - please start logger first.")
    if not db_path.exists():
        raise SystemExit(f"database not found: {db_path}")

    mx = Matrix(cfg["homeserver"], token, int(cfg["max_media_bytes"]))
    bot_user_id = cfg["user_id"]
    if creds_path.exists():
        bot_user_id = json.loads(creds_path.read_text()).get("user_id") or bot_user_id

    app = Flask(__name__, static_folder=None)

    def db() -> sqlite3.Connection:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @functools.lru_cache(maxsize=2048)
    def _read_record(path: str, mtime: float) -> dict[str, Any] | None:
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:
            return None

    def read_record(output_dir: str) -> dict[str, Any] | None:
        p = Path(output_dir) / "event.json"
        if not p.exists():
            return None
        return _read_record(str(p), p.stat().st_mtime)

    def query_in(sql: str, ids: list[str]) -> list[sqlite3.Row]:
        rows: list[sqlite3.Row] = []
        with db() as conn:
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                rows += conn.execute(sql.format(ph=",".join("?" * len(chunk))), chunk).fetchall()
        return rows

    def records_for(ids: list[str]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        if not ids:
            return out
        for r in query_in("SELECT redacted_event_id, output_dir FROM redactions "
                          "WHERE redacted_event_id IN ({ph}) ORDER BY has_original", ids):
            rec = read_record(r["output_dir"])
            if rec:
                out[r["redacted_event_id"]] = rec
        return out

    def cached_for(ids: list[str]) -> dict[str, dict[str, Any]]:
        if not ids:
            return {}
        return {r["event_id"]: json.loads(r["raw"]) for r in query_in(
            "SELECT event_id, raw FROM events WHERE undecrypted=0 AND event_id IN ({ph})", ids)}

    def redaction_info(rec: dict[str, Any] | None, unsigned: dict[str, Any]) -> dict[str, Any]:
        if rec:
            return {"by": rec.get("redacted_by"), "reason": rec.get("reason"),
                    "ts": rec.get("redaction_ts"), "has_record": True}
        because = unsigned.get("redacted_because") or {}
        return {"by": because.get("sender"), "reason": (because.get("content") or {}).get("reason"),
                "ts": because.get("origin_server_ts"), "has_record": False}

    def media_list(event_id: str, content: dict[str, Any], room_id: str, kind_prefix: str = "") -> list:
        items = []
        for ref in extract_media_refs(content):
            if ref["kind"].startswith("new_content_"):
                continue
            kind = kind_prefix + ref["kind"]
            items.append({
                "kind": ref["kind"],
                "mimetype": ref.get("mimetype"),
                "filename": ref.get("filename"),
                "url": f"media?room={quote(room_id, safe='')}&event={quote(event_id, safe='')}"
                       f"&kind={quote(kind, safe='')}",
            })
        return items

    def build_events(raw_events: list[dict[str, Any]], room_id: str,
                     target_id: str | None = None) -> list[dict[str, Any]]:
        ids = [e["event_id"] for e in raw_events if e.get("event_id")]
        records = records_for(ids)
        cached = cached_for(ids)
        out: list[dict[str, Any]] = []

        for ev in raw_events:
            eid = ev.get("event_id")
            if not eid:
                continue
            unsigned = ev.get("unsigned") or {}
            rec = records.get(eid)
            is_redacted = bool(unsigned.get("redacted_because")) or rec is not None
            base, status, red = ev, "normal", None

            if is_redacted:
                red = redaction_info(rec, unsigned)
                if rec and rec.get("has_original") and rec.get("original_event"):
                    base, status = rec["original_event"], "restored"
                elif eid in cached:
                    base, status = cached[eid], "restored"
                else:
                    status = "redacted"
            elif ev.get("type") == "m.room.encrypted":
                if eid in cached:
                    base = cached[eid]
                else:
                    status = "encrypted"

            content = base.get("content") or {}
            sender = ev.get("sender") or base.get("sender")
            etype = base.get("type") or ev.get("type")
            if red is not None:
                red["ban"] = is_ban(etype, red.get("by"))
                red["self"] = bool(red.get("by")) and red.get("by") == sender and not red["ban"]
            item = {
                "event_id": eid,
                "sender": sender,
                "ts": ev.get("origin_server_ts") or base.get("origin_server_ts"),
                "type": etype,
                "state_key": base.get("state_key", ev.get("state_key")),
                "content": content,
                "status": status,
                "redaction": red,
                "is_target": eid == target_id,
                "media": media_list(eid, content, room_id) if status != "redacted" else [],
                "edits": [],
            }
            if rec and status == "restored":
                for e in rec.get("edits") or []:
                    nc = (e.get("content") or {}).get("m.new_content")
                    if isinstance(nc, dict):
                        item["edits"].append({"event_id": e.get("event_id"), "ts": e.get("origin_server_ts"),
                                              "content": nc,
                                              "media": media_list(e["event_id"], nc, room_id, "new_content_")})
            out.append(item)

        by_id = {i["event_id"]: i for i in out}
        for i in out:
            rel = i["content"].get("m.relates_to") if isinstance(i["content"], dict) else None
            if isinstance(rel, dict) and rel.get("rel_type") == "m.replace" and i["status"] != "redacted":
                i["hidden"] = True
                tgt = by_id.get(rel.get("event_id"))
                nc = i["content"].get("m.new_content")
                if tgt and isinstance(nc, dict) and not any(e["event_id"] == i["event_id"] for e in tgt["edits"]):
                    tgt["edits"].append({"event_id": i["event_id"], "ts": i["ts"], "content": nc,
                                         "media": media_list(i["event_id"], nc, room_id, "new_content_")})
        for i in out:
            i["edits"].sort(key=lambda e: e.get("ts") or 0)
        return out

    def members_from_state(state: list[dict[str, Any]]) -> dict[str, str]:
        names = {}
        for s in state or []:
            if s.get("type") == "m.room.member":
                name = (s.get("content") or {}).get("displayname")
                if name:
                    names[s.get("state_key")] = name
        return names

    def local_context(room_id: str, target_id: str, ts: int, limit: int) -> list[dict[str, Any]]:
        with db() as conn:
            before = conn.execute("SELECT raw FROM events WHERE room_id=? AND ts<? ORDER BY ts DESC LIMIT ?",
                                  (room_id, ts, limit)).fetchall()
            after = conn.execute("SELECT raw FROM events WHERE room_id=? AND ts>? ORDER BY ts ASC LIMIT ?",
                                 (room_id, ts, limit)).fetchall()
            same = conn.execute("SELECT raw FROM events WHERE room_id=? AND ts=?", (room_id, ts)).fetchall()
        evs = [json.loads(r["raw"]) for r in reversed(before)]
        evs += [json.loads(r["raw"]) for r in same]
        evs += [json.loads(r["raw"]) for r in after]
        if not any(e.get("event_id") == target_id for e in evs):
            evs.append({"event_id": target_id, "origin_server_ts": ts, "type": "m.room.message",
                        "unsigned": {"redacted_because": {}}})
            evs.sort(key=lambda e: e.get("origin_server_ts") or 0)
        return evs

    def room_summary(room_id: str) -> dict[str, Any]:
        name = (mx.state_event(room_id, "m.room.name") or {}).get("name")
        alias = (mx.state_event(room_id, "m.room.canonical_alias") or {}).get("alias")
        encrypted = mx.state_event(room_id, "m.room.encryption") is not None
        return {"room_id": room_id, "name": name, "alias": alias, "encrypted": encrypted}

    def own_filter(enabled: bool) -> tuple[str, list[Any]]:
        user = web["own_user"]
        if not enabled or not user:
            return "", []
        if web["own_user_role"] == "sender":
            return " AND original_sender=?", [user]
        if web["own_user_role"] == "redacter":
            return " AND redacted_by=?", [user]
        return " AND (original_sender=? OR redacted_by=?)", [user, user]

    def room_event_filter(hide: bool) -> tuple[str, list[Any]]:
        if not hide:
            return "", []
        ph = ",".join("?" * len(ROOM_EVENT_TYPES))
        return f" AND (original_type IS NULL OR original_type NOT IN ({ph}))", list(ROOM_EVENT_TYPES)

    def base_filter(own: bool, hide_room: bool) -> tuple[str, list[Any]]:
        a_sql, a_params = own_filter(own)
        b_sql, b_params = room_event_filter(hide_room)
        return a_sql + b_sql, a_params + b_params

    def is_ban(event_type: str | None, redacted_by: str | None) -> bool:
        if event_type != "m.room.member":
            return False
        return not web["own_user"] or redacted_by == web["own_user"]

    @app.route("/")
    def index():
        try:
            html = TEMPLATE_FILE.read_text(encoding="utf-8")
        except OSError as e:
            return Response(f"Template nicht lesbar: {TEMPLATE_FILE} ({e})",
                            status=500, mimetype="text/plain")
        return Response(html, mimetype="text/html")

    @app.route("/static/<path:filename>")
    def static_files(filename: str):
        return send_from_directory(STATIC_DIR, filename, max_age=86400)

    @app.route("/api/filters")
    def api_filters():
        own_sql, own_params = base_filter(request.args.get("own", "0") == "1",
                                          request.args.get("hide_room", "0") == "1")
        with db() as conn:
            users: dict[str, dict[str, int]] = {}
            for r in conn.execute("SELECT original_sender u, COUNT(*) n FROM redactions "
                                  "WHERE original_sender IS NOT NULL" + own_sql +
                                  " GROUP BY original_sender", own_params):
                users.setdefault(r["u"], {"sender": 0, "redacter": 0})["sender"] = r["n"]
            for r in conn.execute("SELECT redacted_by u, COUNT(*) n FROM redactions "
                                  "WHERE redacted_by IS NOT NULL" + own_sql +
                                  " GROUP BY redacted_by", own_params):
                users.setdefault(r["u"], {"sender": 0, "redacter": 0})["redacter"] = r["n"]
            rooms = [dict(r) for r in conn.execute(
                "SELECT room_id, MAX(room_name) room_name, COUNT(*) n FROM redactions "
                "WHERE 1=1" + own_sql + " GROUP BY room_id ORDER BY room_name", own_params)]
            hs_counts: dict[str, int] = {}
            for r in conn.execute("SELECT original_sender s, redacted_by b FROM redactions "
                                  "WHERE 1=1" + own_sql, own_params):
                for h in {homeserver_of(r["s"]), homeserver_of(r["b"])} - {""}:
                    hs_counts[h] = hs_counts.get(h, 0) + 1
        hs_counts.pop(homeserver_of(web["own_user"]), None)
        return jsonify({
            "users": [{"user_id": u, **c} for u, c in sorted(users.items())],
            "rooms": rooms,
            "homeservers": [{"homeserver": h, "n": n} for h, n in sorted(hs_counts.items())],
            "own_user": web["own_user"],
            "own_user_role": web["own_user_role"],
        })

    @app.route("/api/redactions")
    def api_redactions():
        user = request.args.get("user", "").strip()
        role = request.args.get("role", "any")
        room = request.args.get("room", "").strip()
        homeserver = request.args.get("homeserver", "").strip()
        own = request.args.get("own", "0") == "1" and bool(web["own_user"])
        hide_room = request.args.get("hide_room", "0") == "1"
        q = request.args.get("q", "").strip().lower()

        sql = "SELECT * FROM redactions WHERE 1=1"
        params: list[Any] = []
        if user:
            if role == "sender":
                sql += " AND original_sender=?"
                params.append(user)
            elif role == "redacter":
                sql += " AND redacted_by=?"
                params.append(user)
            else:
                sql += " AND (original_sender=? OR redacted_by=?)"
                params += [user, user]
        if homeserver:
            hs_sender = sql_homeserver("original_sender")
            hs_redacter = sql_homeserver("redacted_by")
            if role == "sender":
                sql += f" AND {hs_sender}=?"
                params.append(homeserver)
            elif role == "redacter":
                sql += f" AND {hs_redacter}=?"
                params.append(homeserver)
            else:
                sql += f" AND ({hs_sender}=? OR {hs_redacter}=?)"
                params += [homeserver, homeserver]
        own_sql, own_params = base_filter(own, hide_room)
        sql += own_sql
        params += own_params
        if room:
            sql += " AND room_id=?"
            params.append(room)
        sql += " ORDER BY COALESCE(redaction_ts, original_ts) DESC LIMIT 1000"

        with db() as conn:
            rows = [dict(r) for r in conn.execute(sql, params)]

        result = []
        for r in rows:
            rec = read_record(r["output_dir"]) or {}
            orig = rec.get("original_event") or {}
            content = orig.get("content") or {}
            preview = content.get("body") if isinstance(content.get("body"), str) else ""
            msgtype = content.get("msgtype") or orig.get("type") or ""
            if q and q not in (preview or "").lower() and q not in (r.get("reason") or "").lower():
                continue
            result.append({
                "redacted_event_id": r["redacted_event_id"],
                "room_id": r["room_id"],
                "room_name": r["room_name"],
                "original_sender": r["original_sender"],
                "original_ts": r["original_ts"],
                "redacted_by": r["redacted_by"],
                "redaction_ts": r["redaction_ts"],
                "reason": r["reason"],
                "has_original": bool(r["has_original"]),
                "media_count": r["media_count"],
                "msgtype": msgtype,
                "preview": (preview or "")[:200],
                "original_type": r["original_type"],
                "state_key": orig.get("state_key"),
                "is_ban": is_ban(r["original_type"], r["redacted_by"]),
                "self_redaction": bool(r["original_sender"]) and r["original_sender"] == r["redacted_by"]
                                  and not is_ban(r["original_type"], r["redacted_by"]),
            })
        return jsonify(result)

    @app.route("/api/context")
    def api_context():
        room_id = request.args.get("room", "")
        event_id = request.args.get("event", "")
        if not room_id or not event_id:
            abort(400)
        limit = int(request.args.get("limit", web["context_limit"]))
        try:
            ctx = mx.context(room_id, event_id, limit)
            raw = list(reversed(ctx.get("events_before") or []))
            raw.append(ctx["event"])
            raw += ctx.get("events_after") or []
            return jsonify({
                "source": "server",
                "events": build_events(raw, room_id, event_id),
                "members": members_from_state(ctx.get("state")),
                "start": ctx.get("start"),
                "end": ctx.get("end"),
            })
        except Exception as e:
            rec = records_for([event_id]).get(event_id) or {}
            ts = rec.get("original_ts") or rec.get("redaction_ts") or 0
            raw = local_context(room_id, event_id, ts, limit)
            return jsonify({
                "source": "cache",
                "warning": f"Could not load history from the server ({e}). Showing the local cache instead.",
                "events": build_events(raw, room_id, event_id),
                "members": {},
                "start": None,
                "end": None,
            })

    @app.route("/api/history")
    def api_history():
        room_id = request.args.get("room", "")
        token_ = request.args.get("from", "")
        direction = "b" if request.args.get("dir", "b") == "b" else "f"
        if not room_id or not token_:
            abort(400)
        try:
            res = mx.messages(room_id, token_, direction, web["context_limit"])
        except Exception as e:
            return jsonify({"error": str(e)}), 502
        chunk = res.get("chunk") or []
        if direction == "b":
            chunk = list(reversed(chunk))
        return jsonify({
            "events": build_events(chunk, room_id),
            "members": members_from_state(res.get("state")),
            "end": res.get("end"),
        })

    @app.route("/api/rooms")
    def api_rooms():
        try:
            room_ids = mx.joined_rooms()
        except Exception as e:
            return jsonify({"error": str(e)}), 502
        with ThreadPoolExecutor(max_workers=8) as pool:
            rooms = list(pool.map(room_summary, room_ids))
        with db() as conn:
            counts = {r["room_id"]: r["n"] for r in conn.execute(
                "SELECT room_id, COUNT(*) n FROM redactions GROUP BY room_id")}
        filtered = set(cfg.get("rooms") or [])
        for r in rooms:
            r["redactions"] = counts.get(r["room_id"], 0)
            r["logged"] = not filtered or r["room_id"] in filtered
        rooms.sort(key=lambda r: (r["name"] or r["alias"] or r["room_id"]).lower())
        return jsonify({"user_id": bot_user_id, "rooms": rooms})

    @app.route("/api/join", methods=["POST"])
    def api_join():
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 415
        body = request.get_json(silent=True) or {}
        room = str(body.get("room", "")).strip()
        via = [s.strip() for s in re.split(r"[,\s]+", str(body.get("via", ""))) if s.strip()]
        if not re.match(r"^[!#][^:\s]+:[^\s]+$", room):
            return jsonify({"error": "Enter a room ID (!abc:server) or alias (#room:server)."}), 400
        if room.startswith("!") and not via:
            via = [room.split(":", 1)[1]]
        try:
            room_id = mx.join(room, via)
        except MatrixError as e:
            return jsonify({"error": f"{e.errcode or 'Error'}: {e.message}"}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 502
        try:
            summary = room_summary(room_id)
        except Exception:
            summary = {"room_id": room_id}
        return jsonify({"ok": True, "room": summary})

    @app.route("/api/leave", methods=["POST"])
    def api_leave():
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 415
        body = request.get_json(silent=True) or {}
        room_id = str(body.get("room_id", "")).strip()
        if not re.match(r"^![^:\s]+:[^\s]+$", room_id):
            return jsonify({"error": "Invalid room ID."}), 400
        try:
            mx.leave(room_id)
        except MatrixError as e:
            return jsonify({"error": f"{e.errcode or 'Error'}: {e.message}"}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 502
        return jsonify({"ok": True, "room_id": room_id})

    @app.route("/media")
    def media():
        room_id = request.args.get("room", "")
        event_id = request.args.get("event", "")
        kind = request.args.get("kind", "main")

        def safe_send(path: str | Path, mimetype: str | None = None):
            p = Path(path).resolve()
            if data_dir not in p.parents or not p.is_file():
                return None
            return send_file(p, mimetype=mimetype, conditional=True)

        with db() as conn:
            for r in conn.execute("SELECT output_dir FROM redactions WHERE redacted_event_id=?", (event_id,)):
                rec = read_record(r["output_dir"]) or {}
                for m in rec.get("media") or []:
                    if m.get("event_id") == event_id and m.get("kind") == kind and m.get("local_file"):
                        resp = safe_send(Path(r["output_dir"]) / m["local_file"], m.get("mimetype"))
                        if resp:
                            return resp
            row = conn.execute("SELECT path, mimetype FROM media WHERE event_id=? AND kind=?",
                               (event_id, kind)).fetchone()
            if row and row["path"]:
                resp = safe_send(row["path"], row["mimetype"])
                if resp:
                    return resp
            crow = conn.execute("SELECT raw FROM events WHERE event_id=? AND undecrypted=0",
                                (event_id,)).fetchone()
        content = json.loads(crow["raw"]).get("content") if crow else None
        if content is None:
            with db() as conn:
                for r in conn.execute("SELECT output_dir FROM redactions WHERE room_id=?", (room_id,)):
                    rec = read_record(r["output_dir"]) or {}
                    for e in [rec.get("original_event") or {}] + (rec.get("edits") or []):
                        if e.get("event_id") == event_id:
                            content = e.get("content")
                            break
                    if content is not None:
                        break
        if content is None and room_id:
            try:
                ev = mx.event(room_id, event_id)
                if ev.get("type") != "m.room.encrypted":
                    content = ev.get("content")
            except Exception:
                pass
        if not content:
            abort(404)

        ref = next((r for r in extract_media_refs(content) if r["kind"] == kind), None)
        if not ref:
            abort(404)
        try:
            data, ctype = mx.download(ref["mxc"])
            enc = ref.get("encrypted_file")
            if enc:
                if decrypt_attachment is None:
                    abort(501)
                data = decrypt_attachment(data, enc["key"]["k"], enc["hashes"]["sha256"], enc["iv"])
                ctype = ref.get("mimetype")
        except Exception:
            abort(502)
        return Response(data, mimetype=ref.get("mimetype") or ctype or "application/octet-stream",
                        headers={"Cache-Control": "private, max-age=86400"})

    @app.after_request
    def security_headers(resp: Response) -> Response:
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
        )
        return resp

    app.config["WEB"] = web
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="web")
    parser.add_argument("--config", "-c", default="config.ini", help="Pfad zur config.ini")
    args = parser.parse_args()
    if not TEMPLATE_FILE.is_file():
        raise SystemExit(f"template not found: {TEMPLATE_FILE}")
    ensure_bootstrap()
    app = create_app(args.config)
    web = app.config["WEB"]
    print(f"redaction viewer running as http://{web['host']}:{web['port']}")
    app.run(host=web["host"], port=web["port"], threaded=True)


if __name__ == "__main__":
    main()