"""Local assertions for integration declarations and evidence capture guards."""

import hashlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

MODULE = importlib.util.spec_from_file_location("cinderlock_kind", Path(__file__).with_name("kind.py"))
KIND = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(KIND)
FIXTURE_MODULE = importlib.util.spec_from_file_location("document_fixture", KIND.PROJECT / "examples/document-qa/app.py")
FIXTURE = importlib.util.module_from_spec(FIXTURE_MODULE)
FIXTURE_MODULE.loader.exec_module(FIXTURE)
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"


class RegistryPrerequisiteTest(unittest.TestCase):
    def observation(self):
        return [dict(Id="a" * 64, Name="/selected-registry", State=dict(Running=True, Status="running"),
                     NetworkSettings=dict(Networks=dict(kind=dict(IPAddress="172.18.0.3"))))]

    def test_every_recipe_has_a_fixed_required_registry_prerequisite(self):
        for version in [1, 2, 3]:
            with self.subTest(version=version):
                routes = [check for check in KIND.workflow_checks(version, FIXTURE) if check["type"] == "endpoint"]
                self.assertEqual(routes, [dict(id="registry-route", type="endpoint", domain="readiness", required=True,
                    url="http://registry-probe:5000/v2/", method="GET", expectedStatus=200, timeoutSeconds=30)])

    def test_registry_observation_requires_exact_running_container_and_kind_address(self):
        observed = KIND.registry_container_observation(self.observation(), "selected-registry")
        self.assertEqual(observed, dict(name="selected-registry", containerID="a" * 64, network="kind", address="172.18.0.3", port=5000))
        bad = []
        for mutate in [lambda item: item.update(Name="/other-registry"),
                       lambda item: item["State"].update(Running=False),
                       lambda item: item["State"].update(Status="paused"),
                       lambda item: item["NetworkSettings"].update(Networks=dict(bridge=dict(IPAddress="172.18.0.3"))),
                       lambda item: item["NetworkSettings"]["Networks"]["kind"].update(IPAddress="127.0.0.1"),
                       lambda item: item["NetworkSettings"]["Networks"]["kind"].update(IPAddress="::1"),
                       lambda item: item["NetworkSettings"]["Networks"]["kind"].update(IPAddress="PRIVATE-OBSERVATION-MARKER")]:
            value = self.observation()
            mutate(value[0])
            bad.append(value)
        bad += [[], self.observation() * 2, None, [dict(Name="/selected-registry")]]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as error:
                    KIND.registry_container_observation(value, "selected-registry")
                self.assertNotIn("PRIVATE-OBSERVATION-MARKER", str(error.exception))

    def test_route_objects_are_namespace_local_and_never_application_owned(self):
        observed = KIND.registry_container_observation(self.observation(), "selected-registry")
        route = KIND.registry_route("lab-namespace", observed)
        self.assertEqual([item["kind"] for item in route["items"]], ["Service", "EndpointSlice"])
        for item in route["items"]:
            self.assertEqual(item["metadata"]["namespace"], "lab-namespace")
            self.assertNotIn("app.kubernetes.io/instance", item["metadata"]["labels"])
        service, endpoints = route["items"]
        self.assertNotIn("selector", service["spec"])
        self.assertEqual(service["spec"]["ports"][0]["port"], 5000)
        self.assertEqual(endpoints["metadata"]["labels"]["kubernetes.io/service-name"], "registry-probe")
        self.assertEqual(endpoints["endpoints"][0]["addresses"], [observed["address"]])
        self.assertEqual(endpoints["ports"][0]["port"], 5000)

    def test_probe_admission_keeps_existing_hosts_and_actions(self):
        site, policy = dict(allowedHosts=["other.internal"], allowedActions=["seed"]), dict(allowedActions=["import"])
        KIND.admit_registry_probe(site, policy)
        before = copy.deepcopy((site, policy))
        KIND.admit_registry_probe(site, policy)
        self.assertEqual((site, policy), before)
        self.assertEqual(site["allowedHosts"], ["other.internal", "registry-probe"])
        self.assertIn("seed", site["allowedActions"])
        self.assertIn("import", policy["allowedActions"])
        for declaration in [site, policy]:
            self.assertTrue({"job", "endpoint-probe", "endpoint-http"} <= set(declaration["allowedActions"]))

    def test_invalid_container_is_rejected_before_namespace_mutation(self):
        lab = object.__new__(KIND.Lab)
        lab.namespace = "test"
        lab.args = SimpleNamespace(registry_container="selected-registry")
        inspected = []

        def inspect(argv, maximum):
            inspected.append(argv)
            return [], "sha256:" + "0" * 64

        lab.json_observation = inspect
        lab.kube = lambda *args: self.fail("namespace mutation preceded registry validation")
        with self.assertRaises(ValueError):
            lab.prepare()
        self.assertEqual(inspected, [["docker", "inspect", "--type", "container", "--", "selected-registry"]])

    def test_private_json_capture_keeps_raw_configuration_out_of_receipts(self):
        lab = object.__new__(KIND.Lab)
        lab.env = {}
        with tempfile.TemporaryDirectory() as directory:
            lab.work = Path(directory)
            private = "PRIVATE-CONTAINER-ENVIRONMENT"
            value = self.observation()
            value[0]["Config"] = dict(Env=[private])
            raw = json.dumps(value).encode()
            with patch.object(KIND.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=raw, stderr=b"")):
                parsed, _ = lab.json_observation(["docker", "inspect"], 1 << 20)
            self.assertNotIn(private, json.dumps(KIND.registry_container_observation(parsed, "selected-registry")))
            for raw in [b'{"secret":"' + private.encode(), b'{"x":1,"x":2}', b"x" * 4097]:
                with patch.object(KIND.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=raw, stderr=b"")):
                    with self.assertRaises(RuntimeError) as error:
                        lab.json_observation(["synthetic-json"], 4096)
                self.assertNotIn(private, str(error.exception))
            self.assertEqual(list(lab.work.iterdir()), [])

    def test_registry_container_argument_is_required_before_any_lab_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            args = [sys.executable, "-B", str(KIND.PROJECT / "tests/integration/kind.py")]
            for key, value in dict(binary="unused", kubeconfig="unused", context="kind-cinderlock-test",
                registry="127.0.0.1:5006", workdir=str(Path(directory) / "run"),
                application_oci="unused", helper_oci="unused", platform="linux/amd64").items():
                args += ["--" + key.replace("_", "-"), value]
            completed = KIND.subprocess.run(args, capture_output=True, text=True, timeout=10)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("--registry-container", completed.stderr)
            self.assertFalse((Path(directory) / "run").exists())

    def test_endpoint_proof_binds_public_worker_before_safe_output(self):
        recipe = "sha256:" + "a" * 64
        check = dict(id="registry-route", type="endpoint", domain="readiness", required=True,
                     url="http://registry-probe:5000/v2/", method="GET", expectedStatus=200, timeoutSeconds=30)
        plan = dict(checks=[check], requiredChecks=[check["id"]], operations=[dict(id="images", type="import"), dict(id="fixtures", type="seed")])
        result = dict(runID="run", checks=[dict(id=check["id"], domain="readiness", required=True, status="pass", evidence="job/route-job")])
        worker = dict(stepID="@check/registry-route", role="@check/registry-route", attempt=1,
                      name="route-job", uid="original-job", recipeDigest=recipe)
        events = [dict(type="worker_bound", seq=3, data=worker),
                  dict(type="operation_outcome", seq=4, data=dict(stepID=worker["stepID"], state="complete")),
                  dict(type="operation_intent", seq=5, data=dict(stepID="fixtures"))]
        container = dict(name="operation", image="127.0.0.1:5006/helper@sha256:" + "c" * 64,
                         command=["/usr/local/bin/cinderlock", "helper", "endpoint-probe"],
                         args=["--url", check["url"], "--method", "GET", "--expected-status", "200", "--timeout-seconds", "30", "--allow-http"])
        payload = dict(apiVersion=KIND.API, kind="CommandResult", command="cinderlock helper endpoint-probe",
                       result=dict(status=200, response="observed", authorization="not_supplied"))
        for case in ["original", "oversized-full-output", "replaced-job", "failed-exit", "wrong-command", "missing-binding"]:
            with self.subTest(case=case):
                lab = object.__new__(KIND.Lab)
                lab.namespace = "test"
                lab.args = SimpleNamespace(registry="127.0.0.1:5006", kubeconfig="lab-only", context="kind-cinderlock-test")
                lab.helper_digest = "sha256:" + "c" * 64
                job = dict(metadata=dict(uid="replacement" if case == "replaced-job" else worker["uid"],
                    labels={"cinderlock.dev/run": "run"}, annotations={"cinderlock.dev/recipe-digest": recipe}),
                    spec=dict(template=dict(spec=dict(containers=[copy.deepcopy(container)]))),
                    status=dict(conditions=[dict(type="Complete", status="True")]))
                if case == "wrong-command":
                    job["spec"]["template"]["spec"]["containers"][0]["command"] = ["/unapproved"]
                pod = dict(metadata=dict(name="route-pod", uid="original-pod", ownerReferences=[dict(
                    apiVersion="batch/v1", kind="Job", name=worker["name"], uid=worker["uid"], controller=True)]),
                    spec=dict(containers=[copy.deepcopy(container)]), status=dict(phase="Succeeded",
                    containerStatuses=[dict(name="operation", state=dict(terminated=dict(exitCode=1 if case == "failed-exit" else 0)))]))
                lab.cli = lambda *args: [] if case == "missing-binding" else events
                lab.kube = lambda *args: json.dumps(job if args[3] == "job" else dict(items=[pod]))
                captured = []

                def observe(argv, maximum):
                    captured.append(argv)
                    return payload, "sha256:" + "d" * 64

                if case == "oversized-full-output":
                    lab.env = {}
                    tail = json.dumps(payload).encode()
                    full = b"UNEXPECTED-LEADING-OUTPUT" + b" " * (4096 - len(tail)) + tail

                    def process(argv, **kwargs):
                        captured.append(argv)
                        truncated = any(arg.startswith("--limit-bytes") for arg in argv)
                        return SimpleNamespace(returncode=0, stdout=full[-4096:] if truncated else full, stderr=b"")

                    with patch.object(KIND.subprocess, "run", side_effect=process):
                        with self.assertRaises(RuntimeError):
                            lab.endpoint_observation(plan, result)
                    self.assertEqual(len(captured), 1)
                    self.assertFalse(any(arg.startswith("--limit-bytes") for arg in captured[0]))
                elif case == "original":
                    lab.json_observation = observe
                    proof = lab.endpoint_observation(plan, result)
                    self.assertEqual(proof["jobUID"], worker["uid"])
                    self.assertEqual(proof["podUID"], pod["metadata"]["uid"])
                    self.assertEqual(proof["exitCode"], 0)
                    self.assertEqual(proof["observation"], payload["result"])
                    self.assertEqual(len(captured), 1)
                    self.assertEqual(captured[0][:5], ["kubectl", "--kubeconfig", "lab-only", "--context", "kind-cinderlock-test"])
                    self.assertFalse(any(arg.startswith("--limit-bytes") for arg in captured[0]))
                else:
                    lab.json_observation = observe
                    with self.assertRaises(AssertionError):
                        lab.endpoint_observation(plan, result)
                    self.assertEqual(captured, [])


class NumericWorkflowTest(unittest.TestCase):
    def test_required_numeric_recipe_preserves_persistence_order_and_optional_negative(self):
        for version in [1, 2, 3]:
            with self.subTest(version=version):
                checks = KIND.workflow_checks(version, FIXTURE)
                self.assertEqual(checks[0]["id"], "health" if version == 1 else "persistence")
                numeric = next(check for check in checks if check["id"] == "numeric-observations")
                self.assertTrue(numeric["required"])
                self.assertEqual(numeric["observationContract"], FIXTURE.observation_contract())
                self.assertIn("observe", numeric["command"])
                self.assertEqual(numeric["fixtures"], ["acceptance-fixture"])
                self.assertEqual(numeric["script"]["successChecks"], [numeric["id"]])
                optional = [check for check in checks if not check["required"]]
                self.assertEqual([check["id"] for check in optional], ["numeric-budget-negative"] if version == 2 else [])
                if optional:
                    negative = optional[0]
                    self.assertEqual(negative["command"][-4:], ["--memory-limit-bytes", "0", "--fixture", "/cinderlock-fixtures/acceptance-fixture/document.json"])
                    self.assertEqual(negative["observationContract"], FIXTURE.observation_contract(memory_limit_bytes=0))
                    self.assertNotIn(negative["id"], [check["id"] for check in checks if check["required"]])

    def test_replaced_job_is_rejected_before_reading_any_output(self):
        lab = object.__new__(KIND.Lab)
        lab.namespace = "test"
        calls = []
        source = dict(jobName="numeric-job", jobUID="original-job", podName="numeric-pod", podUID="original-pod",
                      recipeDigest="sha256:" + "a" * 64, outputDigest="sha256:" + "b" * 64)

        def kube(*args):
            calls.append(args)
            self.assertNotIn("logs", args)
            return json.dumps(dict(metadata=dict(uid="replacement-job")))

        lab.kube = kube
        with self.assertRaises(AssertionError):
            lab.observation_output(source, "run")
        self.assertEqual(len(calls), 1)

    def test_numeric_output_requires_unique_original_pod_before_and_after_read(self):
        output = '{"samples":[]}\n'
        source = dict(jobName="numeric-job", jobUID="original-job", podName="numeric-pod", podUID="original-pod",
                      recipeDigest="sha256:" + "a" * 64, outputDigest="sha256:" + hashlib.sha256(output.encode()).hexdigest())
        for case in ["original", "two-pods", "replaced-after-read"]:
            with self.subTest(case=case):
                lab = object.__new__(KIND.Lab)
                lab.namespace = "test"
                job = dict(metadata=dict(uid=source["jobUID"], labels={"cinderlock.dev/run": "run"},
                    annotations={"cinderlock.dev/recipe-digest": source["recipeDigest"]}),
                    status=dict(conditions=[dict(type="Complete", status="True")]))
                pod = dict(metadata=dict(name=source["podName"], uid=source["podUID"],
                    ownerReferences=[dict(apiVersion="batch/v1", kind="Job", name=source["jobName"],
                                          uid=source["jobUID"], controller=True)]), status=dict(phase="Succeeded"))
                reads = []

                def kube(*args):
                    if "logs" in args:
                        reads.append(args)
                        if case == "replaced-after-read":
                            pod["metadata"]["uid"] = "replacement"
                        return output
                    return json.dumps(job if args[3] == "job" else dict(items=[pod] * (2 if case == "two-pods" else 1)))

                lab.kube = kube
                if case == "original":
                    self.assertEqual(lab.observation_output(source, "run"), {"samples": []})
                else:
                    with self.assertRaises(AssertionError):
                        lab.observation_output(source, "run")
                self.assertEqual(len(reads), 0 if case == "two-pods" else 1)


class HelperIdentityTest(unittest.TestCase):
    def test_script_contract_names_actual_fixture_effect_and_rejects_unknown_recipe(self):
        restore = KIND.Lab.job("restore", "job", ["restore", "--backup", "/data/test.sqlite"])
        self.assertEqual(restore["script"]["successChecks"], ["persistence", "query"])
        self.assertIn("Replace synthetic fixture data", restore["script"]["sideEffects"][0])
        self.assertEqual(restore["command"], ["python", "/app/app.py", "restore", "--backup", "/data/test.sqlite"])
        with self.assertRaises(KeyError):
            KIND.Lab.job("unknown", "job", ["unclassified-mutation"])

    def archive(self, directory, entries, blobs):
        path = Path(directory) / "helper.tar"
        documents = {"index.json": json.dumps(dict(schemaVersion=2, manifests=entries)).encode()}
        documents.update({"blobs/sha256/" + digest[7:]: data for digest, data in blobs.items()})
        with tarfile.open(path, "w") as archive:
            for name, data in documents.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return path

    @staticmethod
    def descriptor(value, media_type=MANIFEST, ref=None, platform=None):
        data = json.dumps(value, sort_keys=True).encode()
        descriptor = dict(mediaType=media_type, digest="sha256:" + hashlib.sha256(data).hexdigest(), size=len(data))
        if ref:
            descriptor["annotations"] = {"org.opencontainers.image.ref.name": ref}
        if platform:
            descriptor["platform"] = platform
        return descriptor, data

    def test_ref_one_does_not_select_the_first_other_tag(self):
        old, old_data = self.descriptor(dict(schemaVersion=2, label="other"), ref="old")
        selected, data = self.descriptor(dict(schemaVersion=2, label="selected"), ref="1")
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory, [old, selected], {old["digest"]: old_data, selected["digest"]: data})
            self.assertEqual(KIND.helper_manifest_digest(path, "linux/arm64"), selected["digest"])

    def test_index_selects_one_matching_platform(self):
        amd, amd_data = self.descriptor(dict(schemaVersion=2, label="amd"), platform=dict(os="linux", architecture="amd64"))
        arm, arm_data = self.descriptor(dict(schemaVersion=2, label="arm"), platform=dict(os="linux", architecture="arm64"))
        index, index_data = self.descriptor(dict(schemaVersion=2, manifests=[amd, arm]), INDEX, ref="1")
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory, [index], {index["digest"]: index_data, amd["digest"]: amd_data, arm["digest"]: arm_data})
            self.assertEqual(KIND.helper_manifest_digest(path, "linux/arm64"), arm["digest"])
            with self.assertRaises(ValueError):
                KIND.helper_manifest_digest(path, "linux/s390x")

    def test_ambiguous_reference_and_tampered_descriptor_fail(self):
        selected, data = self.descriptor(dict(schemaVersion=2), ref="1")
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory, [selected, selected], {selected["digest"]: data})
            with self.assertRaises(ValueError):
                KIND.helper_manifest_digest(path, "linux/arm64")
            path = self.archive(directory, [selected], {selected["digest"]: b'{"schemaVersion":2,"tampered":true}'})
            with self.assertRaises(ValueError):
                KIND.helper_manifest_digest(path, "linux/arm64")


if __name__ == "__main__":
    unittest.main()
