"""Pure local assertions for the integration runner's helper-image pinning."""

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
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"


class HelperIdentityTest(unittest.TestCase):
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
