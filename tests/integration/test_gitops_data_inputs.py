"""Ownership and recipe checks before the persistent GitOps live rehearsal."""

import copy
import importlib.util
from pathlib import Path
import sys
import unittest


def module(name, path):
    definition = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(definition)
    sys.modules[name] = value
    definition.loader.exec_module(value)
    return value


HERE = Path(__file__).resolve().parent
DATA = module("gitops_data_inputs", HERE / "gitops_data_inputs.py")
REFERENCE = module("data_reference_inputs", HERE / "reference_inputs.py")
APP = module("data_fixture_app", HERE.parents[1] / "examples/document-qa/app.py")


class PersistentGitOpsInputsTest(unittest.TestCase):
    def test_native_data_effects_survive_the_adoption_cut(self):
        for number in [1, 2, 3]:
            with self.subTest(number=number):
                release, original = DATA.release_declaration(REFERENCE, number, "a" * 40, "linux/arm64", APP)
                spec = release["spec"]
                ops = {op["id"]: op for op in spec["operations"]}
                old = {op["id"]: op for op in original["spec"]["operations"]}
                self.assertEqual(spec["checks"], original["spec"]["checks"])
                self.assertEqual(spec["requiredChecks"], original["spec"]["requiredChecks"])
                for name in ["quiesce", "backup", "schema", "synthetic-data-loss", "writes"]:
                    if name in old:
                        self.assertEqual(ops[name]["command"], old[name]["command"])
                        self.assertEqual(ops[name]["script"], old[name]["script"])
                self.assertEqual(ops["deploy"]["type"], "gitops")
                self.assertEqual(set(ops["deploy"]), {"id", "type", "dependsOn", "idempotent"})
                self.assertEqual(ops["acceptance-fixtures"]["dependsOn"], ["deploy"])
                self.assertEqual(ops["models"]["dependsOn"], ["images"])
                self.assertEqual(ops["restart"]["type"], "job")
                self.assertEqual(ops["restart"]["script"]["retry"], "manual")
                self.assertFalse(ops["restart"]["idempotent"])
                self.assertTrue(all(op["type"] not in ["helm", "restart"] for op in ops.values()))
                if number == 3:
                    recovery = spec["recovery"][0]
                    restore = next(op for op in recovery["operations"] if op["id"] == "restore-fixture")
                    previous = next(op for op in original["spec"]["recovery"][0]["operations"] if op["id"] == "restore-fixture")
                    self.assertEqual(restore, previous)
                    self.assertEqual(recovery["gitOpsData"]["resume"], "recovery-writes")
                    self.assertEqual(recovery["operations"][-1]["type"], "job")
                else:
                    recovery = spec["recovery"][0]
                    self.assertEqual(recovery["id"], original["spec"]["recovery"][0]["id"])
                    self.assertEqual(recovery["operations"][-1]["id"], "repair-restart")
                    self.assertIn("mode=ro", next(op for op in recovery["operations"] if op["id"] == "repair-data-check")["command"][2])
                    self.assertEqual(recovery["checks"], original["spec"]["recovery"][0]["checks"])

    def api(self, foreign=False, changed=False):
        deployment = dict(metadata=dict(name="document-qa", uid="original-deployment"), spec=dict(selector=dict(matchLabels={"app": "document-qa"})))
        rs = dict(metadata=dict(uid="original-rs", ownerReferences=[dict(apiVersion="apps/v1", kind="Deployment", name="document-qa", uid="original-deployment", controller=True)]))
        pod = dict(metadata=dict(name="original-pod", namespace="test", uid="original-pod-uid", resourceVersion="17", labels={"app": "document-qa"}, ownerReferences=[dict(apiVersion="apps/v1", kind="ReplicaSet", name="application-rs", uid="original-rs", controller=True)]), status=dict(conditions=[dict(type="Ready", status="True")]))
        if foreign:
            rs["metadata"]["ownerReferences"][0]["uid"] = "foreign-deployment"
        deletes = []

        def request(method, path, body=None):
            if method == "DELETE":
                self.assertEqual(path, "/api/v1/namespaces/test/pods/original-pod")
                self.assertEqual(body["preconditions"], dict(uid="original-pod-uid", resourceVersion="17"))
                deletes.append(copy.deepcopy(body))
                return {}
            if path.endswith("/deployments/document-qa"):
                current = copy.deepcopy(deployment)
                if changed and deletes:
                    current["spec"]["replicas"] = 2
                return current
            if path.endswith("/replicasets/application-rs"):
                return copy.deepcopy(rs)
            self.assertEqual(path, "/api/v1/namespaces/test/pods?limit=257")
            current = copy.deepcopy(pod)
            if deletes:
                current["metadata"].update(name="replacement-pod", uid="replacement-pod-uid", resourceVersion="19")
            return dict(items=[current])
        return request, deletes

    def test_restart_deletes_only_original_pod_and_observes_replacement(self):
        request, deletes = self.api()
        result = DATA.restart_application(request, "test", "original-deployment", lambda _: self.fail("ready replacement was already observed"))
        self.assertEqual(result, dict(restarted=True, originalPodUID="original-pod-uid", replacementPodUID="replacement-pod-uid"))
        self.assertEqual(len(deletes), 1)
        compile(DATA.restart_command()[2], "signed-restart", "exec")
        with self.assertRaisesRegex(RuntimeError, "cannot follow redirects"):
            DATA.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.invalid")

    def test_unrelated_owner_or_changed_deployment_never_supplies_restart_proof(self):
        request, deletes = self.api(foreign=True)
        with self.assertRaises(AssertionError):
            DATA.restart_application(request, "test", "original-deployment", lambda _: None)
        self.assertEqual(deletes, [])
        request, deletes = self.api(changed=True)
        with self.assertRaises(AssertionError):
            DATA.restart_application(request, "test", "original-deployment", lambda _: None)
        self.assertEqual(len(deletes), 1)


if __name__ == "__main__":
    unittest.main()
