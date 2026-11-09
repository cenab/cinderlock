#!/usr/bin/env python3
"""Synthetic document-QA delivery fixture. This is not an LLM or GPU workload."""

import argparse
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import tracemalloc
import urllib.error
import urllib.parse
import urllib.request
import uuid

APP_ID = 0x434C434B
MAX_REQUEST = 65536
MAX_OBSERVATION_MEMORY = 16 << 20
DOCUMENT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
HERE = Path(__file__).resolve().parent


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def file_hash(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            result.update(chunk)
    return "sha256:" + result.hexdigest()


def unique_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def read_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_REQUEST:
        raise ValueError("fixture input must be a bounded regular file")
    return json.loads(path.read_text(), object_pairs_hook=unique_keys)


def models(directory):
    directory = Path(directory)
    model, tokenizer = read_json(directory / "model.json"), read_json(directory / "tokenizer.json")
    if model.get("kind") != "synthetic-lexical" or model.get("scoring") != "token-overlap":
        raise ValueError("unsupported synthetic model")
    if tokenizer.get("kind") != "synthetic-tokenizer" or tokenizer.get("lowercase") is not True:
        raise ValueError("unsupported tokenizer")
    if not model.get("revision") or model["revision"] != tokenizer.get("revision"):
        raise ValueError("model/tokenizer revisions differ")
    return {
        "revision": model["revision"],
        "modelDigest": file_hash(directory / "model.json"),
        "tokenizerDigest": file_hash(directory / "tokenizer.json"),
    }


@contextlib.contextmanager
def database(path, initialize=False):
    path = Path(path)
    if initialize:
        path.parent.mkdir(parents=True, exist_ok=True)
    elif not path.is_file():
        raise ValueError("fixture database does not exist")
    db = sqlite3.connect(str(path), timeout=5)
    db.row_factory = sqlite3.Row
    try:
        application = db.execute("PRAGMA application_id").fetchone()[0]
        tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        if application == 0 and not tables and initialize:
            db.execute("PRAGMA journal_mode=WAL")
            with db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("CREATE TABLE metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
                db.execute("CREATE TABLE documents (id TEXT PRIMARY KEY, text TEXT NOT NULL, model_revision TEXT NOT NULL)")
                db.execute("CREATE TABLE operations (id TEXT PRIMARY KEY, kind TEXT NOT NULL, target_schema INTEGER NOT NULL, status TEXT NOT NULL, input_digest TEXT NOT NULL)")
                db.execute("INSERT INTO metadata(name,value) VALUES('instance_id',?),('maintenance','0')", (str(uuid.uuid4()),))
                db.execute("PRAGMA application_id=" + str(APP_ID))
                db.execute("PRAGMA user_version=1")
        elif application != APP_ID:
            raise ValueError("database is not the Cinderlock synthetic fixture")
        if db.execute("PRAGMA user_version").fetchone()[0] not in (1, 2):
            raise ValueError("unsupported fixture schema")
        db.execute("PRAGMA busy_timeout=5000")
        yield db
    finally:
        db.close()


def metadata(db, name):
    row = db.execute("SELECT value FROM metadata WHERE name=?", (name,)).fetchone()
    if row is None:
        raise ValueError("fixture metadata missing")
    return row[0]


def schema(db):
    return db.execute("PRAGMA user_version").fetchone()[0]


def maintenance(path, enabled):
    with database(path) as db, db:
        db.execute("BEGIN IMMEDIATE")
        changed = db.execute("UPDATE metadata SET value=? WHERE name='maintenance'", ("1" if enabled else "0",))
        if changed.rowcount != 1:
            raise ValueError("maintenance metadata missing")
    return {"maintenance": enabled}


def migrate(path, target, operation):
    if target != 2 or not operation or len(operation) > 512:
        raise ValueError("only the declared fixture schema 1 -> 2 transition is supported")
    with database(path) as db, db:
        db.execute("BEGIN IMMEDIATE")
        if metadata(db, "maintenance") != "1":
            raise ValueError("quiesce fixture writes before migrating")
        row = db.execute("SELECT target_schema,status,input_digest,kind FROM operations WHERE id=?", (operation,)).fetchone()
        if row and (row[0] != target or row[1] != "committed" or row[2] != "schema:2" or row[3] != "migration"):
            raise ValueError("operation identity conflicts with prior work")
        if schema(db) == 1:
            db.execute("ALTER TABLE documents ADD COLUMN normalized TEXT NOT NULL DEFAULT ''")
            db.execute("UPDATE documents SET normalized=lower(text)")
            db.execute("PRAGMA user_version=2")
        if "normalized" not in [r[1] for r in db.execute("PRAGMA table_info(documents)")]:
            raise ValueError("target schema postcondition is absent")
        db.execute("INSERT INTO operations(id,kind,target_schema,status,input_digest) VALUES(?,'migration',2,'committed','schema:2') ON CONFLICT DO NOTHING", (operation,))
    return {"operation": operation, "schema": 2, "status": "committed"}


def reconcile(path, operation):
    with database(path) as db:
        row = db.execute("SELECT target_schema,status FROM operations WHERE id=?", (operation,)).fetchone()
        if row is None or row[1] != "committed" or row[0] != schema(db):
            raise ValueError("operation completion is not established")
        return {"operation": operation, "schema": schema(db), "status": row[1]}


def backup(path, output, operation):
    if not operation or len(operation) > 512:
        raise ValueError("bounded backup operation identity required")
    output = Path(output)
    manifest = Path(str(output) + ".manifest.json")
    with database(path) as db:
        if metadata(db, "maintenance") != "1":
            raise ValueError("quiesce fixture writes before backup")
        instance = metadata(db, "instance_id")
        if output.exists() or manifest.exists():
            saved = verify_backup(output, instance)
            if saved["operation"] != operation:
                raise ValueError("backup belongs to another operation; choose a new backup destination")
            return saved
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            with contextlib.closing(sqlite3.connect(str(output))) as copy:
                db.backup(copy)
                if copy.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("backup integrity check failed")
            result = {"kind": "SyntheticFixtureBackup", "instance": instance, "schema": schema(db), "digest": file_hash(output), "operation": operation}
            manifest_fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(manifest_fd, "w") as target:
                json.dump(result, target, sort_keys=True)
                target.flush()
                os.fsync(target.fileno())
            return result
        except Exception:
            output.unlink(missing_ok=True)
            manifest.unlink(missing_ok=True)
            raise


def verify_backup(path, instance):
    path = Path(path)
    result = read_json(str(path) + ".manifest.json")
    if path.is_symlink() or result.get("kind") != "SyntheticFixtureBackup" or result.get("instance") != instance or result.get("digest") != file_hash(path):
        raise ValueError("backup identity or digest mismatch")
    with database(path) as copy:
        if copy.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or schema(copy) != result["schema"] or metadata(copy, "instance_id") != instance:
            raise ValueError("backup schema/data integrity mismatch")
    return result


def restore(path, source, authorized, operation):
    if not operation or len(operation) > 512:
        raise ValueError("bounded restore operation identity required")
    if not authorized:
        raise ValueError("restore requires explicit --authorize-test-restore; use only on approved test data")
    with database(path) as db:
        if metadata(db, "maintenance") != "1":
            raise ValueError("quiesce fixture writes before restore")
        result = verify_backup(source, metadata(db, "instance_id"))
        previous = db.execute("SELECT kind,input_digest,target_schema,status FROM operations WHERE id=?", (operation,)).fetchone()
        if previous:
            if tuple(previous) != ("restore", result["digest"], result["schema"], "committed") or schema(db) != result["schema"]:
                raise ValueError("restore operation conflicts with prior work")
            return {"status": "already-restored", "schema": result["schema"], "backupDigest": result["digest"], "operation": operation}
        with database(source) as copy:
            copy.backup(db)
        with db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE metadata SET value='1' WHERE name='maintenance'")
            db.execute("INSERT INTO operations(id,kind,target_schema,status,input_digest) VALUES(?,'restore',?,'committed',?)", (operation, result["schema"], result["digest"]))
    return {"status": "restored", "schema": result["schema"], "backupDigest": result["digest"], "operation": operation}


def seed(source, destination):
    source, destination = Path(source), Path(destination)
    revision = models(source)
    destination.mkdir(parents=True, exist_ok=True)
    marker = destination / ".fixture-ready.json"
    if marker.exists():
        if read_json(marker) != revision or models(destination) != revision:
            raise ValueError("existing model revision differs or is corrupt")
        return revision
    for name in ("model.json", "tokenizer.json"):
        target = destination / name
        if target.exists():
            if target.is_symlink() or file_hash(target) != file_hash(source / name):
                raise ValueError("partial model destination conflicts with declared source")
            continue
        fd, temporary = tempfile.mkstemp(prefix=".seed-", dir=destination)
        try:
            with os.fdopen(fd, "wb") as output, (source / name).open("rb") as input_file:
                shutil.copyfileobj(input_file, output)
                output.flush()
                os.fsync(output.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                if target.is_symlink() or file_hash(target) != file_hash(source / name):
                    raise ValueError("concurrent model publication differs")
        finally:
            Path(temporary).unlink(missing_ok=True)
    if models(destination) != revision:
        raise ValueError("materialized model differs")
    fd, temporary = tempfile.mkstemp(prefix=".ready-", dir=destination)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(revision, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, marker)
        except FileExistsError:
            if read_json(marker) != revision:
                raise ValueError("concurrent model marker differs")
    finally:
        Path(temporary).unlink(missing_ok=True)
    return revision


def make_handler(path, model_dir, version, required_schema, maintenance_ready=False):
    revision = models(model_dir)

    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_):
            pass

        def respond(self, status, value):
            body = json.dumps(value, sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            route = urllib.parse.urlsplit(self.path)
            try:
                with database(path) as db:
                    current = schema(db)
                    paused = metadata(db, "maintenance") == "1"
                    ready = current == required_schema
                    if route.path == "/health":
                        healthy = ready or maintenance_ready and paused and required_schema == 1 and current == 2
                        return self.respond(200 if healthy else 503, {"ready": healthy, "schema": current, "requiredSchema": required_schema, "maintenance": paused})
                    if route.path == "/version":
                        return self.respond(200, {"application": "document-qa-fixture", "version": version, "schema": current, "workload": "synthetic-lexical-not-llm", **revision})
                    if not ready or paused:
                        return self.respond(503, {"error": "fixture is quiesced or schema does not match"})
                    if route.path.startswith("/documents/"):
                        identifier = urllib.parse.unquote(route.path.removeprefix("/documents/"))
                        if not DOCUMENT_ID.fullmatch(identifier):
                            return self.respond(400, {"error": "invalid document ID"})
                        row = db.execute("SELECT id,text,model_revision FROM documents WHERE id=?", (identifier,)).fetchone()
                        return self.respond(200, dict(row)) if row else self.respond(404, {"error": "document absent"})
                    if route.path == "/query":
                        query = urllib.parse.parse_qs(route.query).get("q", [""])[0]
                        if not query or len(query) > 128:
                            return self.respond(400, {"error": "bounded query required"})
                        tokens = set(re.findall(r"[a-z0-9]+", query.lower()))
                        matches = []
                        for row in db.execute("SELECT id,text FROM documents LIMIT 10000"):
                            score = len(tokens.intersection(re.findall(r"[a-z0-9]+", row["text"].lower())))
                            if score:
                                matches.append({"id": row["id"], "text": row["text"], "score": score})
                        matches.sort(key=lambda item: (-item["score"], item["id"]))
                        return self.respond(200, {"matches": matches[:10], "workload": "synthetic-lexical-not-llm"})
                    self.respond(404, {"error": "route absent"})
            except (ValueError, sqlite3.Error, OSError):
                self.respond(503, {"error": "fixture state unavailable"})

        def do_POST(self):
            if self.path != "/documents":
                return self.respond(404, {"error": "route absent"})
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size < 1 or size > MAX_REQUEST or self.headers.get("Transfer-Encoding"):
                    raise ValueError("bounded Content-Length required")
                value = json.loads(self.rfile.read(size), object_pairs_hook=unique_keys)
                if set(value) != {"id", "text"} or not isinstance(value["id"], str) or not DOCUMENT_ID.fullmatch(value["id"]) or not isinstance(value["text"], str) or not value["text"].strip() or len(value["text"]) > 32768:
                    raise ValueError("invalid synthetic document")
                with database(path) as db, db:
                    db.execute("BEGIN IMMEDIATE")
                    if metadata(db, "maintenance") != "0" or schema(db) != required_schema:
                        return self.respond(503, {"error": "fixture is quiesced or schema does not match"})
                    if schema(db) == 2:
                        db.execute("INSERT INTO documents(id,text,model_revision,normalized) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET text=excluded.text,model_revision=excluded.model_revision,normalized=excluded.normalized", (value["id"], value["text"], revision["revision"], value["text"].lower()))
                    else:
                        db.execute("INSERT INTO documents(id,text,model_revision) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET text=excluded.text,model_revision=excluded.model_revision", (value["id"], value["text"], revision["revision"]))
                self.respond(200, {"id": value["id"], "stored": True})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError, RecursionError):
                self.respond(400, {"error": "invalid bounded JSON document"})
            except (sqlite3.Error, OSError):
                self.respond(503, {"error": "fixture database unavailable"})

    return Handler


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise ValueError("probe redirects are not permitted")


def probe(base_url, check, fixture_path=None):
    url = urllib.parse.urlsplit(base_url)
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.query or url.fragment:
        raise ValueError("explicit internal HTTP(S) base URL required")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(path, value=None):
        body = json.dumps(value).encode() if value is not None else None
        request = urllib.request.Request(base_url.rstrip("/") + path, data=body, headers={"Content-Type": "application/json"})
        try:
            opened = opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            raise ValueError("probe HTTP status " + str(status)) from None
        with opened as response:
            data = response.read(MAX_REQUEST + 1)
            if len(data) > MAX_REQUEST or response.status != 200:
                raise ValueError("probe response invalid")
            return json.loads(data, object_pairs_hook=unique_keys)

    fixture = {"id": "cinderlock-fixture-redwood", "text": "The synthetic redwood fixture lives in the local forest."}
    if fixture_path is not None:
        fixture = read_json(fixture_path)
        if not isinstance(fixture, dict) or set(fixture) != {"id", "text"} or not isinstance(fixture["id"], str) or not DOCUMENT_ID.fullmatch(fixture["id"]) or not isinstance(fixture["text"], str) or not fixture["text"].strip() or len(fixture["text"]) > 32768:
            raise ValueError("invalid staged synthetic document")
    if check == "health":
        if call("/health").get("ready") is not True:
            raise ValueError("health not ready")
    elif check == "ingestion":
        call("/documents", fixture)
        if call("/documents/" + fixture["id"]).get("text") != fixture["text"]:
            raise ValueError("ingestion failed")
    elif check == "query":
        matches = call("/query?q=redwood").get("matches", [])
        if not any(item.get("id") == fixture["id"] for item in matches):
            raise ValueError("synthetic retrieval failed")
    elif check == "persistence":
        if call("/documents/" + fixture["id"]).get("text") != fixture["text"]:
            raise ValueError("previously ingested fixture did not persist")
    else:
        raise ValueError("unsupported probe")
    return {"check": check, "status": "pass", "workload": "synthetic-lexical-not-llm"}


def observation_contract(memory_limit_bytes=MAX_OBSERVATION_MEMORY):
    if type(memory_limit_bytes) is not int or not 0 <= memory_limit_bytes <= MAX_OBSERVATION_MEMORY:
        raise ValueError("memory limit must be an integer from 0 to 16777216 bytes")
    return {
        "version": 1,
        "testRevision": "document-qa-persistence-client-1",
        "assertionRevision": "fixture-client-tracemalloc-1",
        "profile": "kubernetes-cpu-lab",
        "sampleCount": 3,
        "sampling": {"http-reads-per-sample": 1, "concurrency": 1, "retries": 0},
        "nondeterminism": "HTTP latency and traced Python allocation vary with scheduling, interpreter state and caches.",
        "limitations": (
            "Client traced Python allocation excludes serving/native/RSS/GPU memory. "
            "Only three synthetic reads, not performance/profile qualification. "
            "Serving, image, registry and node-cache warmth are unknown."
        ),
        "metrics": [
            {"name": "fixture-match", "kind": "assertion", "unit": "count", "min": 1, "max": 1,
             "assertion": "The existing persistence probe matches the staged fixture text; success yields 1 and ValueError yields 0."},
            {"name": "probe-latency", "kind": "latency", "unit": "microseconds", "min": 0, "max": 20000000,
             "assertion": "Client elapsed time for one persistence probe from perf_counter_ns, truncated to integer microseconds."},
            {"name": "client-traced-peak", "kind": "resource", "unit": "bytes", "min": 0, "max": memory_limit_bytes,
             "assertion": "Python test-client peak allocation traced by tracemalloc around one persistence probe; excludes serving/native/RSS/GPU memory."},
        ],
    }


def observe(base_url, fixture_path, memory_limit_bytes=MAX_OBSERVATION_MEMORY):
    contract = observation_contract(memory_limit_bytes)
    samples = []
    for index in range(1, contract["sampleCount"] + 1):
        matched = 1
        tracemalloc.start()
        tracemalloc.clear_traces()
        started = time.perf_counter_ns()
        try:
            probe(base_url, "persistence", fixture_path)
        except ValueError:
            matched = 0
        finally:
            elapsed = (time.perf_counter_ns() - started) // 1000
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        samples.append({
            "index": index,
            "metrics": [{"name": metric["name"], "unit": metric["unit"], "value": value}
                        for metric, value in zip(contract["metrics"], (matched, elapsed, peak), strict=True)],
        })
    # Sorted compact JSON matches canonical JSON for this fixed ASCII safe-integer contract.
    body = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {
        "version": contract["version"],
        "contractDigest": "sha256:" + hashlib.sha256(body).hexdigest(),
        "profile": contract["profile"],
        "runtime": "python-test-client-" + sys.version.split()[0],
        "device": "cpu",
        "mode": "client-tracemalloc",
        "warmCold": "unknown",
        "concurrency": contract["sampling"]["concurrency"],
        "samples": samples,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=os.environ.get("FIXTURE_DATABASE", "/data/app.sqlite"))
    sub = parser.add_subparsers(dest="command", required=True)
    server = sub.add_parser("serve")
    server.add_argument("--host", default="0.0.0.0")
    server.add_argument("--port", type=int, default=8080)
    server.add_argument("--model-dir", default=os.environ.get("MODEL_DIR", str(HERE / "models")))
    server.add_argument("--version", default=os.environ.get("APP_VERSION", "1.0.0"))
    server.add_argument("--schema", type=int, default=int(os.environ.get("SCHEMA_TARGET", "1")))
    server.add_argument("--maintenance-ready", action="store_true", default=os.environ.get("MAINTENANCE_READY") == "1",
                        help="Keep the quiesced schema-1 server healthy during the synthetic schema-2 migration")
    check = sub.add_parser("probe")
    check.add_argument("--base-url", required=True)
    check.add_argument("--check", choices=["health", "ingestion", "query", "persistence"], required=True)
    check.add_argument("--fixture", help="Read the synthetic document from a staged JSON file")
    observation = sub.add_parser("observe")
    observation.add_argument("--base-url", required=True)
    observation.add_argument("--fixture", required=True)
    observation.add_argument("--memory-limit-bytes", type=int, default=MAX_OBSERVATION_MEMORY)
    sub.add_parser("quiesce")
    sub.add_parser("resume-writes")
    migration = sub.add_parser("migrate")
    migration.add_argument("--to", type=int, required=True)
    migration.add_argument("--operation-id", default="schema-v1-v2")
    reconciliation = sub.add_parser("reconcile")
    reconciliation.add_argument("--operation-id", required=True)
    saving = sub.add_parser("backup")
    saving.add_argument("--out", required=True)
    saving.add_argument("--operation-id", default=os.environ.get("CINDERLOCK_OPERATION_ID", "manual-backup"))
    recovery = sub.add_parser("restore")
    recovery.add_argument("--backup", required=True)
    recovery.add_argument("--operation-id", default=os.environ.get("CINDERLOCK_OPERATION_ID", "manual-restore"))
    recovery.add_argument("--authorize-test-restore", action="store_true")
    seeding = sub.add_parser("seed")
    seeding.add_argument("--source", default=str(HERE / "models"))
    seeding.add_argument("--destination", required=True)
    args = parser.parse_args()
    try:
        if args.command == "serve":
            with database(args.database, initialize=True):
                pass
            handler = make_handler(args.database, args.model_dir, args.version, args.schema, args.maintenance_ready)
            with http.server.ThreadingHTTPServer((args.host, args.port), handler) as httpd:
                emit({"state": "listening", "port": args.port, "workload": "synthetic-lexical-not-llm"})
                httpd.serve_forever()
            return
        if args.command == "probe": result = probe(args.base_url, args.check, args.fixture)
        elif args.command == "observe": result = observe(args.base_url, args.fixture, args.memory_limit_bytes)
        elif args.command == "quiesce": result = maintenance(args.database, True)
        elif args.command == "resume-writes": result = maintenance(args.database, False)
        elif args.command == "migrate": result = migrate(args.database, args.to, args.operation_id)
        elif args.command == "reconcile": result = reconcile(args.database, args.operation_id)
        elif args.command == "backup": result = backup(args.database, args.out, args.operation_id)
        elif args.command == "restore": result = restore(args.database, args.backup, args.authorize_test_restore, args.operation_id)
        elif args.command == "seed": result = seed(args.source, args.destination)
        else: raise ValueError("unsupported command")
        emit(result)
    except (ValueError, sqlite3.Error, OSError, urllib.error.URLError) as exc:
        if args.command != "observe":
            emit({"status": "fail", "error": str(exc), "workload": "synthetic-lexical-not-llm"})
        sys.exit(1)


if __name__ == "__main__":
    main()
