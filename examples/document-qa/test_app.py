import concurrent.futures
import http.server
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location("fixture", Path(__file__).with_name("app.py"))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class DeliveryFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "app.sqlite"
        with app.database(self.database, initialize=True):
            pass
        self.server = None
        self.start()
        self.addCleanup(self.stop)

    def start(self, schema=1):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), app.make_handler(self.database, app.HERE / "models", "fixture-test", schema))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_port)

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)
            self.server = None

    def call(self, path, value=None):
        body = json.dumps(value).encode() if value is not None else None
        request = urllib.request.Request(self.base + path, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def test_ingestion_query_and_real_process_state_restart(self):
        app.probe(self.base, "ingestion")
        app.probe(self.base, "query")
        self.stop()
        self.start()
        self.assertEqual(app.probe(self.base, "persistence")["status"], "pass")
        self.assertEqual(self.call("/version")["workload"], "synthetic-lexical-not-llm")

    def test_probe_consumes_staged_document_and_checks_it_after_restart(self):
        fixture = self.root / "document.json"
        document = {"id": "staged-redwood", "text": "A different synthetic redwood document comes from the staged fixture."}
        fixture.write_text(json.dumps(document))
        app.probe(self.base, "ingestion", fixture)
        self.assertEqual(self.call("/documents/staged-redwood")["text"], document["text"])
        self.stop()
        self.start()
        self.assertEqual(app.probe(self.base, "persistence", fixture)["status"], "pass")
        with self.assertRaises(ValueError):
            app.probe(self.base, "persistence")
        fixture.write_text(json.dumps({"id": "staged-redwood", "text": ["invalid"]}))
        with self.assertRaises(ValueError):
            app.probe(self.base, "ingestion", fixture)

    def test_migration_commit_reconciliation_and_test_copy_restore(self):
        app.probe(self.base, "ingestion")
        app.maintenance(self.database, True)
        self.assertTrue(self.call("/health")["maintenance"])
        with self.assertRaises(ValueError):
            app.probe(self.base, "persistence")
        saved = self.root / "backup.sqlite"
        first = app.backup(self.database, saved, "backup-run-1")
        self.assertEqual(first, app.backup(self.database, saved, "backup-run-1"))
        with self.assertRaises(ValueError):
            app.backup(self.database, saved, "different-run")
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            jobs = [pool.submit(app.migrate, self.database, 2, "schema-v1-v2") for _ in range(2)]
            self.assertTrue(all(job.result()["status"] == "committed" for job in jobs))
        self.assertEqual(app.reconcile(self.database, "schema-v1-v2")["schema"], 2)
        self.stop()
        self.start(schema=2)
        app.maintenance(self.database, False)
        app.probe(self.base, "persistence")
        self.call("/documents", {"id": "after-backup", "text": "This later synthetic document must disappear after restore."})
        app.maintenance(self.database, True)
        with self.assertRaises(ValueError):
            app.restore(self.database, saved, False, "restore-run-1")
        result = app.restore(self.database, saved, True, "restore-run-1")
        self.assertEqual(result["schema"], 1)
        self.assertEqual(app.restore(self.database, saved, True, "restore-run-1")["status"], "already-restored")
        self.stop()
        self.start(schema=1)
        app.maintenance(self.database, False)
        app.probe(self.base, "persistence")
        with self.assertRaises(urllib.error.HTTPError) as absent:
            self.call("/documents/after-backup")
        self.assertEqual(absent.exception.code, 404)
        absent.exception.close()
        self.assertEqual(app.reconcile(self.database, "restore-run-1")["schema"], 1)
        with self.assertRaises(ValueError):
            app.reconcile(self.database, "schema-v1-v2")

    def test_corrupt_or_foreign_backup_refuses_restore(self):
        app.maintenance(self.database, True)
        saved = self.root / "backup.sqlite"
        app.backup(self.database, saved, "backup-run-1")
        with saved.open("r+b") as output:
            output.seek(128)
            output.write(b"corruption")
        with self.assertRaises(ValueError):
            app.restore(self.database, saved, True, "restore-run-1")
        with app.database(self.database) as db:
            self.assertEqual(app.schema(db), 1)

    def test_migration_requires_quiescence_and_cannot_reconcile_absent_commit(self):
        with self.assertRaises(ValueError):
            app.migrate(self.database, 2, "schema-v1-v2")
        with self.assertRaises(ValueError):
            app.reconcile(self.database, "schema-v1-v2")
        with app.database(self.database) as db:
            self.assertEqual(app.schema(db), 1)

    def test_model_seeding_is_complete_concurrent_and_tamper_checked(self):
        destination = self.root / "model-revision"
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            jobs = [pool.submit(app.seed, app.HERE / "models", destination) for _ in range(2)]
            results = [job.result() for job in jobs]
        self.assertEqual(results[0], results[1])
        self.assertEqual(app.models(destination), app.read_json(destination / ".fixture-ready.json"))
        (destination / "model.json").write_text("{}")
        with self.assertRaises(ValueError):
            app.seed(app.HERE / "models", destination)

    def test_missing_or_mismatched_models_fail_startup(self):
        empty = self.root / "empty-models"
        empty.mkdir()
        with self.assertRaises((ValueError, FileNotFoundError)):
            app.make_handler(self.database, empty, "broken", 1)
        (empty / "model.json").write_text((app.HERE / "models/model.json").read_text())
        (empty / "tokenizer.json").write_text('{"kind":"synthetic-tokenizer","revision":"different","lowercase":true}')
        with self.assertRaises(ValueError):
            app.models(empty)

    def test_duplicate_document_keys_and_invalid_ids_are_rejected(self):
        for body in [b'{"id":"x","id":"y","text":"z"}', b'{"id":"../../escape","text":"z"}']:
            request = urllib.request.Request(self.base + "/documents", data=body, headers={"Content-Type": "application/json"})
            with self.assertRaises(urllib.error.HTTPError) as invalid:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(invalid.exception.code, 400)
            invalid.exception.close()

    def test_probe_does_not_follow_redirect_to_another_service(self):
        class Redirect(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/never-contact")
                self.end_headers()

        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertRaises(ValueError):
                    app.probe("http://127.0.0.1:" + str(server.server_port), "health")
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
