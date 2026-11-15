#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import configparser
import json
import logging
import mimetypes
import os
import re
import shutil
import signal
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp
from nio import (
    AsyncClient,
    AsyncClientConfig,
    BadEvent,
    Event,
    InviteMemberEvent,
    JoinError,
    LoginResponse,
    MatrixRoom,
    MegolmEvent,
    RedactedEvent,
    RedactionEvent,
    UnknownBadEvent,
)

try:
    from nio.crypto import ENCRYPTION_ENABLED
except ImportError:
    ENCRYPTION_ENABLED = False

try:
    from nio.crypto.attachments import decrypt_attachment
except ImportError:
    decrypt_attachment = None

log = logging.getLogger("redaction-logger")

DEFAULT_CONFIG: dict[str, Any] = {
    "homeserver": "",
    "user_id": "",
    "password": "",
    "access_token": "",
    "device_id": "",
    "device_name": "redaction-logger",
    "data_dir": "./data",
    "rooms": [],
    "prefetch_media": True,
    "max_media_bytes": 100 * 1024 * 1024,
    "cache_retention_days": 30,
    "timeline_limit": 100,
    "auto_join_invites": True,
    "invite_allowlist": [],
}

ENV_MAP = {
    "MATRIX_HOMESERVER": "homeserver",
    "MATRIX_USER_ID": "user_id",
    "MATRIX_PASSWORD": "password",
    "MATRIX_ACCESS_TOKEN": "access_token",
    "MATRIX_DEVICE_ID": "device_id",
    "MATRIX_DATA_DIR": "data_dir",
}


def safe_name(value: str, max_len: int = 80) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "").strip("._")
    return (value or "unnamed")[:max_len]


def ts_to_iso(ts_ms: int | None) -> str | None:
    if not ts_ms:
        return None
    return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).astimezone().isoformat()


def ts_to_dirname(ts_ms: int | None) -> str:
    if not ts_ms:
        ts_ms = int(time.time() * 1000)
    return datetime.fromtimestamp(ts_ms / 1000).strftime("%Y-%m-%d_%H-%M-%S")


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    i = 1
    while True:
        candidate = path.with_name(f"{stem}_{i}{suffix}")
        if not candidate.exists():
            return candidate
        i += 1


def extract_media_refs(content: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    if not isinstance(content, dict):
        return refs

    info = content.get("info") if isinstance(content.get("info"), dict) else {}
    filename = content.get("filename") or content.get("body") or "media"
    if not isinstance(filename, str):
        filename = "media"

    def add(kind: str, url: Any, enc: Any, name: str, mimetype: str | None) -> None:
        if isinstance(enc, dict) and isinstance(enc.get("url"), str) and enc["url"].startswith("mxc://"):
            refs.append({"kind": kind, "mxc": enc["url"], "encrypted_file": enc,
                         "filename": name, "mimetype": enc.get("mimetype") or mimetype})
        elif isinstance(url, str) and url.startswith("mxc://"):
            refs.append({"kind": kind, "mxc": url, "encrypted_file": None,
                         "filename": name, "mimetype": mimetype})

    add("main", content.get("url"), content.get("file"), filename, info.get("mimetype"))

    thumb_info = info.get("thumbnail_info") if isinstance(info.get("thumbnail_info"), dict) else {}
    add("thumbnail", info.get("thumbnail_url"), info.get("thumbnail_file"),
        f"thumbnail_{filename}", thumb_info.get("mimetype"))

    new_content = content.get("m.new_content")
    if isinstance(new_content, dict):
        for ref in extract_media_refs(new_content):
            ref["kind"] = f"new_content_{ref['kind']}"
            refs.append(ref)

    return refs


def event_to_dict(event: Any, room_id: str) -> dict[str, Any]:
    src = event.source if isinstance(getattr(event, "source", None), dict) else {}
    d: dict[str, Any] = {
        "event_id": getattr(event, "event_id", None) or src.get("event_id"),
        "room_id": room_id,
        "sender": getattr(event, "sender", None) or src.get("sender"),
        "origin_server_ts": getattr(event, "server_timestamp", None) or src.get("origin_server_ts"),
        "type": src.get("type") or type(event).__name__,
        "content": src.get("content") or {},
        "unsigned": src.get("unsigned") or {},
    }
    if "state_key" in src:
        d["state_key"] = src["state_key"]
    if getattr(event, "decrypted", False):
        d["was_encrypted"] = True
    return d

class Database:
    def __init__(self, path: Path) -> None:
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id     TEXT PRIMARY KEY,
                room_id      TEXT NOT NULL,
                sender       TEXT,
                ts           INTEGER,
                type         TEXT,
                undecrypted  INTEGER DEFAULT 0,
                relates_to   TEXT,
                rel_type     TEXT,
                raw          TEXT NOT NULL,
                received_at  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_relates ON events(relates_to);
            CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at);

            CREATE TABLE IF NOT EXISTS media (
                event_id  TEXT NOT NULL,
                kind      TEXT NOT NULL,
                mxc       TEXT,
                path      TEXT,
                filename  TEXT,
                mimetype  TEXT,
                size      INTEGER,
                error     TEXT,
                PRIMARY KEY (event_id, kind)
            );

            CREATE TABLE IF NOT EXISTS redactions (
                redacted_event_id   TEXT NOT NULL,
                redaction_event_id  TEXT NOT NULL,
                room_id             TEXT NOT NULL,
                room_name           TEXT,
                redacted_by         TEXT,
                reason              TEXT,
                redaction_ts        INTEGER,
                original_sender     TEXT,
                original_ts         INTEGER,
                original_type       TEXT,
                has_original        INTEGER,
                media_count         INTEGER,
                output_dir          TEXT,
                logged_at           INTEGER,
                PRIMARY KEY (redacted_event_id, redaction_event_id)
            );
            """
        )
        self.conn.commit()

    def cache_event(self, ev: dict[str, Any], undecrypted: bool = False) -> bool:
        rel = ev.get("content", {}).get("m.relates_to") if isinstance(ev.get("content"), dict) else None
        relates_to = rel.get("event_id") if isinstance(rel, dict) else None
        rel_type = rel.get("rel_type") if isinstance(rel, dict) else None
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO events
               (event_id, room_id, sender, ts, type, undecrypted, relates_to, rel_type, raw, received_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (ev["event_id"], ev["room_id"], ev.get("sender"), ev.get("origin_server_ts"),
             ev.get("type"), int(undecrypted), relates_to, rel_type,
             json.dumps(ev, ensure_ascii=False), int(time.time())),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def update_event(self, ev: dict[str, Any]) -> None:
        self.conn.execute(
            "UPDATE events SET raw=?, type=?, undecrypted=0 WHERE event_id=?",
            (json.dumps(ev, ensure_ascii=False), ev.get("type"), ev["event_id"]),
        )
        self.conn.commit()

    def get_event(self, event_id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()

    def get_edits(self, event_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT raw FROM events WHERE relates_to=? AND rel_type='m.replace' ORDER BY ts",
            (event_id,),
        ).fetchall()
        return [json.loads(r["raw"]) for r in rows]

    def save_media(self, event_id: str, ref: dict[str, Any], result: dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO media (event_id, kind, mxc, path, filename, mimetype, size, error)
               VALUES (?,?,?,?,?,?,?,?)""",
            (event_id, ref["kind"], ref["mxc"], result.get("path"), ref.get("filename"),
             result.get("mimetype"), result.get("size"), result.get("error")),
        )
        self.conn.commit()

    def get_media(self, event_id: str) -> dict[str, sqlite3.Row]:
        rows = self.conn.execute("SELECT * FROM media WHERE event_id=?", (event_id,)).fetchall()
        return {r["kind"]: r for r in rows}

    def redaction_exists(self, redacted_id: str, redaction_id: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM redactions WHERE redacted_event_id=? AND redaction_event_id=?",
            (redacted_id, redaction_id),
        ).fetchone() is not None

    def save_redaction(self, rec: dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT OR IGNORE INTO redactions
               (redacted_event_id, redaction_event_id, room_id, room_name, redacted_by, reason,
                redaction_ts, original_sender, original_ts, original_type, has_original,
                media_count, output_dir, logged_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rec["redacted_event_id"], rec["redaction_event_id"], rec["room_id"], rec["room_name"],
             rec["redacted_by"], rec["reason"], rec["redaction_ts"], rec["original_sender"],
             rec["original_ts"], rec["original_type"], int(rec["has_original"]),
             rec["media_count"], rec["output_dir"], int(time.time())),
        )
        self.conn.commit()

    def prune(self, older_than: int) -> list[str]:
        rows = self.conn.execute(
            "SELECT event_id FROM events WHERE received_at < ?", (older_than,)
        ).fetchall()
        ids = [r["event_id"] for r in rows]
        if ids:
            self.conn.executemany("DELETE FROM events WHERE event_id=?", [(i,) for i in ids])
            self.conn.executemany("DELETE FROM media WHERE event_id=?", [(i,) for i in ids])
            self.conn.commit()
        return ids


class RedactionLogger:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg
        self.homeserver = cfg["homeserver"].rstrip("/")
        self.data_dir = Path(cfg["data_dir"]).expanduser().resolve()
        self.store_dir = self.data_dir / "store"
        self.cache_media_dir = self.data_dir / "cache_media"
        self.output_dir = self.data_dir / "redactions"
        self.jsonl_path = self.data_dir / "redactions.jsonl"
        self.creds_path = self.data_dir / "credentials.json"
        for d in (self.data_dir, self.store_dir, self.cache_media_dir, self.output_dir):
            d.mkdir(parents=True, exist_ok=True)

        self.db = Database(self.data_dir / "redaction_logger.db")
        self.room_filter = set(cfg.get("rooms") or [])
        self.http: aiohttp.ClientSession | None = None
        self._joining: set[str] = set()

        client_config = AsyncClientConfig(
            store_sync_tokens=True,
            encryption_enabled=ENCRYPTION_ENABLED,
            max_limit_exceeded=0,
            max_timeouts=0,
        )
        self.client = AsyncClient(
            self.homeserver,
            cfg["user_id"],
            device_id=cfg.get("device_id") or None,
            store_path=str(self.store_dir),
            config=client_config,
        )

    async def login(self) -> None:
        if self.creds_path.exists():
            creds = json.loads(self.creds_path.read_text())
            self.client.restore_login(creds["user_id"], creds["device_id"], creds["access_token"])
            log.info("login restored (%s, device %s)", creds["user_id"], creds["device_id"])
            return

        if self.cfg.get("access_token"):
            if not self.cfg.get("device_id"):
                raise SystemExit("Bei Login per access_token muss auch device_id gesetzt sein.")
            self.client.restore_login(self.cfg["user_id"], self.cfg["device_id"], self.cfg["access_token"])
            log.info("Login via Access-Token (device %s)", self.cfg["device_id"])
            return

        if not self.cfg.get("password"):
            raise SystemExit("neither password nor access token configured!")

        resp = await self.client.login(self.cfg["password"], device_name=self.cfg["device_name"])
        if not isinstance(resp, LoginResponse):
            raise SystemExit(f"Login failed: {resp}")
        self.creds_path.write_text(json.dumps({
            "user_id": resp.user_id,
            "device_id": resp.device_id,
            "access_token": resp.access_token,
        }, indent=2))
        os.chmod(self.creds_path, 0o600)
        log.info("logged in as %s (device %s). credentials saved.", resp.user_id, resp.device_id)

    def room_wanted(self, room_id: str) -> bool:
        return not self.room_filter or room_id in self.room_filter

    def room_name(self, room_id: str) -> str:
        room = self.client.rooms.get(room_id)
        if room is None:
            return room_id
        try:
            return room.display_name or room_id
        except Exception:
            return room_id

    async def download_mxc(self, mxc: str) -> tuple[bytes, str | None]:
        m = re.match(r"^mxc://([^/]+)/([^/?#]+)", mxc)
        if not m:
            raise ValueError(f"invalid mxc-URL: {mxc}")
        server, media_id = m.group(1), m.group(2)
        assert self.http is not None
        headers = {"Authorization": f"Bearer {self.client.access_token}"}
        max_bytes = int(self.cfg["max_media_bytes"])
        endpoints = [
            f"{self.homeserver}/_matrix/client/v1/media/download/{server}/{media_id}",
            f"{self.homeserver}/_matrix/media/v3/download/{server}/{media_id}",
        ]
        last_error = "unknown"
        for url in endpoints:
            try:
                async with self.http.get(url, headers=headers, params={"allow_redirect": "true"}) as r:
                    if r.status != 200:
                        last_error = f"HTTP {r.status}: {(await r.text())[:200]}"
                        continue
                    if r.content_length and r.content_length > max_bytes:
                        raise ValueError(f"file to large ({r.content_length} Bytes)")
                    buf = bytearray()
                    async for chunk in r.content.iter_chunked(65536):
                        buf.extend(chunk)
                        if len(buf) > max_bytes:
                            raise ValueError(f"file to large (> {max_bytes} Bytes)")
                    return bytes(buf), r.headers.get("Content-Type")
            except aiohttp.ClientError as e:
                last_error = str(e)
        raise RuntimeError(f"Download failed ({mxc}): {last_error}")

    async def download_ref(self, ref: dict[str, Any], target_dir: Path) -> dict[str, Any]:
        try:
            data, content_type = await self.download_mxc(ref["mxc"])
            enc = ref.get("encrypted_file")
            if enc:
                if decrypt_attachment is None:
                    raise RuntimeError("decryption not available (pycryptodome missing)")
                data = decrypt_attachment(data, enc["key"]["k"], enc["hashes"]["sha256"], enc["iv"])
                content_type = ref.get("mimetype") or "application/octet-stream"

            mimetype = ref.get("mimetype") or (content_type or "").split(";")[0] or None
            name = safe_name(ref.get("filename") or "media", 120)
            if not Path(name).suffix and mimetype:
                name += mimetypes.guess_extension(mimetype) or ""

            target_dir.mkdir(parents=True, exist_ok=True)
            path = unique_path(target_dir / name)
            path.write_bytes(data)
            return {"path": str(path), "size": len(data), "mimetype": mimetype}
        except Exception as e:
            log.warning("media %s not loaded: %s", ref.get("mxc"), e)
            return {"error": str(e)}

    async def prefetch_media(self, event_id: str, content: dict[str, Any]) -> None:
        for ref in extract_media_refs(content):
            result = await self.download_ref(ref, self.cache_media_dir / safe_name(event_id))
            self.db.save_media(event_id, ref, result)

    def try_decrypt_cached(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        if not ENCRYPTION_ENABLED or self.client.olm is None:
            return None
        try:
            megolm = MegolmEvent.from_dict(raw)
            if not isinstance(megolm, MegolmEvent):
                return None
            megolm.room_id = raw["room_id"]
            decrypted = self.client.decrypt_event(megolm)
            return event_to_dict(decrypted, raw["room_id"])
        except Exception as e:
            log.debug("decryption failed: %s", e)
            return None

    async def on_invite(self, room: MatrixRoom, event: InviteMemberEvent) -> None:
        if event.state_key != self.client.user_id or event.membership != "invite":
            return
        if not self.cfg.get("auto_join_invites", True):
            log.info("invite to %s from %s ignored (auto_join_invites = no)", room.room_id, event.sender)
            return
        allow = self.cfg.get("invite_allowlist") or []
        if allow and event.sender not in allow and not any(
            event.sender.endswith(":" + a.lstrip(":")) for a in allow if not a.startswith("@")
        ):
            log.info("invite to %s from %s declined (not in invite_allowlist)", room.room_id, event.sender)
            return
        if room.room_id in self._joining:
            return
        self._joining.add(room.room_id)
        try:
            for attempt in range(3):
                resp = await self.client.join(room.room_id)
                if not isinstance(resp, JoinError):
                    log.info("invite from %s accepted, joined room %s", event.sender, room.room_id)
                    return
                log.warning("join to %s failed (try %d): %s", room.room_id, attempt + 1, resp.message)
                await asyncio.sleep(5 * (attempt + 1))
        finally:
            self._joining.discard(room.room_id)

    async def on_event(self, room: MatrixRoom, event: Any) -> None:
        if room.room_id in self.client.invited_rooms:
            return
        if not self.room_wanted(room.room_id):
            return
        try:
            src = getattr(event, "source", {}) or {}

            if isinstance(event, RedactionEvent) or src.get("type") == "m.room.redaction":
                await self.handle_redaction_event(room, event, src)
            elif isinstance(event, RedactedEvent) or (src.get("unsigned") or {}).get("redacted_because"):
                await self.handle_already_redacted(room, src)
            elif isinstance(event, MegolmEvent):
                raw = dict(src)
                raw["room_id"] = room.room_id
                self.db.cache_event(raw, undecrypted=True)
                log.debug("not decryptable event: %s", event.event_id)
                try:
                    await self.client.request_room_key(event)
                except Exception:
                    pass
            elif isinstance(event, Event):
                ev = event_to_dict(event, room.room_id)
                if ev["event_id"] and self.db.cache_event(ev) and self.cfg.get("prefetch_media"):
                    if extract_media_refs(ev["content"]):
                        asyncio.create_task(self.prefetch_media(ev["event_id"], ev["content"]))
        except Exception:
            log.exception("error at event handling")

    async def handle_redaction_event(self, room: MatrixRoom, event: Any, src: dict[str, Any]) -> None:
        content = src.get("content") or {}
        redacts = getattr(event, "redacts", None) or src.get("redacts") or content.get("redacts")
        if not redacts:
            log.warning("redaction without target: %s", src.get("event_id"))
            return
        await self.record_redaction(
            room_id=room.room_id,
            redacted_event_id=redacts,
            redaction_event_id=src.get("event_id") or getattr(event, "event_id", ""),
            redacted_by=src.get("sender") or getattr(event, "sender", None),
            reason=getattr(event, "reason", None) or content.get("reason"),
            redaction_ts=src.get("origin_server_ts") or getattr(event, "server_timestamp", None),
            fallback_event=None,
        )

    async def handle_already_redacted(self, room: MatrixRoom, src: dict[str, Any]) -> None:
        because = (src.get("unsigned") or {}).get("redacted_because") or {}
        await self.record_redaction(
            room_id=room.room_id,
            redacted_event_id=src.get("event_id", ""),
            redaction_event_id=because.get("event_id", "unknown"),
            redacted_by=because.get("sender"),
            reason=(because.get("content") or {}).get("reason"),
            redaction_ts=because.get("origin_server_ts"),
            fallback_event={**src, "room_id": room.room_id},
        )

    async def record_redaction(
        self,
        room_id: str,
        redacted_event_id: str,
        redaction_event_id: str,
        redacted_by: str | None,
        reason: str | None,
        redaction_ts: int | None,
        fallback_event: dict[str, Any] | None,
    ) -> None:
        if self.db.redaction_exists(redacted_event_id, redaction_event_id):
            return

        row = self.db.get_event(redacted_event_id)
        original: dict[str, Any] | None = json.loads(row["raw"]) if row else None
        note = None

        if row and row["undecrypted"]:
            decrypted = self.try_decrypt_cached(original)
            if decrypted:
                original = decrypted
                self.db.update_event(decrypted)
            else:
                note = "missing decryption key"

        has_original = original is not None and not (row and row["undecrypted"] and note)
        if original is None:
            note = ("original event wasn't received."
                    "(Script was offline or event older as cache). content not available.")

        room_name = self.room_name(room_id)
        ref_event = original or fallback_event or {}
        original_ts = ref_event.get("origin_server_ts")

        out_dir = unique_path(
            self.output_dir
            / f"{safe_name(room_name, 50)}__{safe_name(room_id, 60)}"
            / f"{ts_to_dirname(original_ts or redaction_ts)}_{safe_name(redacted_event_id, 60)}"
        )
        out_dir.mkdir(parents=True, exist_ok=True)

        media_out: list[dict[str, Any]] = []
        edits = self.db.get_edits(redacted_event_id) if has_original else []
        media_sources: list[tuple[str, dict[str, Any]]] = []
        if has_original:
            media_sources.append((redacted_event_id, original.get("content") or {}))
            for e in edits:
                media_sources.append((e["event_id"], e.get("content") or {}))

        for ev_id, content in media_sources:
            cached = self.db.get_media(ev_id)
            for ref in extract_media_refs(content):
                entry = {"event_id": ev_id, "kind": ref["kind"], "mxc": ref["mxc"],
                         "filename": ref.get("filename"), "mimetype": ref.get("mimetype"),
                         "encrypted": bool(ref.get("encrypted_file"))}
                crow = cached.get(ref["kind"])
                if crow is not None and crow["path"] and Path(crow["path"]).exists():
                    dest = unique_path(out_dir / Path(crow["path"]).name)
                    shutil.copy2(crow["path"], dest)
                    entry.update(local_file=dest.name, size=crow["size"], source="cache")
                else:
                    res = await self.download_ref(ref, out_dir)
                    if res.get("path"):
                        entry.update(local_file=Path(res["path"]).name, size=res["size"],
                                     source="download_after_redaction")
                    else:
                        entry.update(local_file=None, error=res.get("error"))
                media_out.append(entry)

        record = {
            "room_id": room_id,
            "room_name": room_name,
            "redacted_event_id": redacted_event_id,
            "redaction_event_id": redaction_event_id,
            "redacted_by": redacted_by,
            "reason": reason,
            "redaction_ts": redaction_ts,
            "redaction_time": ts_to_iso(redaction_ts),
            "original_sender": ref_event.get("sender"),
            "original_ts": original_ts,
            "original_time": ts_to_iso(original_ts),
            "original_type": ref_event.get("type"),
            "has_original": has_original,
            "note": note,
            "original_event": original if has_original else None,
            "edits": edits,
            "media": media_out,
            "media_count": sum(1 for m in media_out if m.get("local_file")),
            "output_dir": str(out_dir),
            "logged_at": datetime.now().astimezone().isoformat(),
        }

        (out_dir / "event.json").write_text(json.dumps(record, ensure_ascii=False, indent=2))
        with self.jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.db.save_redaction(record)

        body = ""
        if has_original:
            b = (original.get("content") or {}).get("body")
            if isinstance(b, str):
                body = f' "{b[:80]}"'
        log.info(
            "REDACTED in %s | %s from %s, deleted by %s%s%s | Media: %d",
            room_name, ts_to_iso(original_ts) or "?", record["original_sender"] or "?",
            redacted_by or "?", f" (reason: {reason})" if reason else "", body, record["media_count"],
        )

    async def prune_loop(self) -> None:
        days = float(self.cfg.get("cache_retention_days") or 0)
        if days <= 0:
            return
        while True:
            cutoff = int(time.time() - days * 86400)
            ids = self.db.prune(cutoff)
            for event_id in ids:
                shutil.rmtree(self.cache_media_dir / safe_name(event_id), ignore_errors=True)
            if ids:
                log.info("cache clearer: remove %d events", len(ids))
            await asyncio.sleep(3600)

    async def run(self) -> None:
        self.http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600))
        prune_task: asyncio.Task | None = None
        try:
            await self.login()
            if ENCRYPTION_ENABLED:
                log.info("E2EE active - encrypted rooms can be parsed.")
            else:
                log.warning("E2EE not available (matrix-nio[e2e] / libolm missing) - "
                            "encrypted messages won't be parsed.")

            self.client.add_event_callback(self.on_invite, InviteMemberEvent)
            self.client.add_event_callback(self.on_event, (Event, BadEvent, UnknownBadEvent))
            prune_task = asyncio.create_task(self.prune_loop())

            sync_filter = {"room": {"timeline": {"limit": int(self.cfg.get("timeline_limit", 100))}}}
            log.info("start sync. files: %s", self.data_dir)
            await self.client.sync_forever(timeout=30000, full_state=True, sync_filter=sync_filter)
        finally:
            if prune_task:
                prune_task.cancel()
            await self.client.close()
            await self.http.close()


def load_config(path: str | None) -> dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    if path:
        if not Path(path).exists():
            raise SystemExit(f"config missing: {path}")
        ini = configparser.ConfigParser(interpolation=None)
        ini.read(path, encoding="utf-8")

        if ini.has_section("matrix"):
            sec = ini["matrix"]
            for key in ("homeserver", "user_id", "password", "access_token", "device_id", "device_name"):
                if sec.get(key, "").strip():
                    cfg[key] = sec.get(key).strip()

        if ini.has_section("logger"):
            sec = ini["logger"]
            if sec.get("data_dir", "").strip():
                cfg["data_dir"] = sec.get("data_dir").strip()
            rooms = sec.get("rooms", "")
            cfg["rooms"] = [r.strip() for r in re.split(r"[,\s]+", rooms) if r.strip()]
            cfg["prefetch_media"] = sec.getboolean("prefetch_media", fallback=cfg["prefetch_media"])
            cfg["max_media_mb"] = sec.getfloat("max_media_mb", fallback=cfg["max_media_bytes"] / 1048576)
            cfg["max_media_bytes"] = int(cfg["max_media_mb"] * 1024 * 1024)
            cfg["cache_retention_days"] = sec.getfloat("cache_retention_days",
                                                       fallback=cfg["cache_retention_days"])
            cfg["timeline_limit"] = sec.getint("timeline_limit", fallback=cfg["timeline_limit"])
            cfg["log_level"] = sec.get("log_level", "INFO").strip().upper()
            cfg["auto_join_invites"] = sec.getboolean("auto_join_invites", fallback=cfg["auto_join_invites"])
            allow = sec.get("invite_allowlist", "")
            cfg["invite_allowlist"] = [u.strip() for u in re.split(r"[,\s]+", allow) if u.strip()]

    for env, key in ENV_MAP.items():
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    if not cfg["homeserver"] or not cfg["user_id"]:
        raise SystemExit("homeserver and user_id missing.")
    return cfg


def main() -> None:
    parser = argparse.ArgumentParser(description="log redacted matrix messages.")
    parser.add_argument("--config", "-c", default="config.ini",
                        help="path to config.ini (default: ./config.ini)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug")
    args = parser.parse_args()

    cfg = load_config(args.config)
    level = "DEBUG" if args.verbose else cfg.get("log_level", "INFO")
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(message)s",
    )
    if level != "DEBUG":
        logging.getLogger("nio").setLevel(logging.WARNING)

    logger = RedactionLogger(cfg)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    main_task = loop.create_task(logger.run())
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, main_task.cancel)
        except NotImplementedError:
            pass
    try:
        loop.run_until_complete(main_task)
    except asyncio.CancelledError:
        log.info("stopped")
    finally:
        loop.close()


if __name__ == "__main__":
    main()