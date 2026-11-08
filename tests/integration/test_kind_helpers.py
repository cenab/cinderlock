"""Local assertions for integration declarations and evidence capture guards."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

MODULE = importlib.util.spec_from_file_location("cinderlock_kind", Path(__file__).with_name("kind.py"))
KIND = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(KIND)
FIXTURE_MODULE = importlib.util.spec_from_file_location("document_fixture", KIND.PROJECT / "examples/document-qa/app.py")
FIXTURE = importlib.util.module_from_spec(FIXTURE_MODULE)
FIXTURE_MODULE.loader.exec_module(FIXTURE)
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"


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
