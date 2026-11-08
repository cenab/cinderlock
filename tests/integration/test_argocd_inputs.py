"""Local protocol checks for the disposable Argo qualification inputs."""

import base64
import functools
import gzip
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

MODULE = importlib.util.spec_from_file_location("argocd_inputs", Path(__file__).with_name("argocd.py"))
ARGO = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(ARGO)


class SourceTransportTest(unittest.TestCase):
    def test_bare_source_advertises_refs_without_host_config_or_hooks(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            repository = work / "repository"
            repository.mkdir()
            ARGO.fixture_git(repository, "init", "--initial-branch=fixture", "--template=")
            (repository / "application.yaml").write_text("kind: ConfigMap\n")
            ARGO.fixture_git(repository, "add", "--", "application.yaml")
            ARGO.fixture_git(repository, "commit", "-m", "Synthetic fixture base")
            ARGO.prepare_bare_repository(repository, work / "source.git")
            bare = work / "source.git"
            advertised = (bare / "info/refs").read_bytes().split()[0]
            self.assertEqual(advertised, ARGO.fixture_git(repository, "rev-parse", "HEAD").strip())
            self.assertNotIn(str(repository), (bare / "config").read_text())
            self.assertNotIn("remote", (bare / "config").read_text())
            self.assertFalse((bare / "hooks").exists())
            original = next((repository / ".git/objects").glob("??/*"))
            self.assertNotEqual(original.stat().st_ino, (bare / "objects" / original.relative_to(repository / ".git/objects")).stat().st_ino)

    def test_bare_repository_serves_the_accepted_commit_over_http(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            repository = work / "repository"
            repository.mkdir()
            templates = work / "empty-templates"
            templates.mkdir()
            ARGO.fixture_git(repository, "init", "--initial-branch=fixture", "--template=" + str(templates))
            (repository / "application.yaml").write_text("kind: ConfigMap\ndata: {phase: base}\n")
            ARGO.fixture_git(repository, "add", "--", "application.yaml")
            ARGO.fixture_git(repository, "commit", "-m", "Synthetic fixture base")
            base = ARGO.fixture_git(repository, "rev-parse", "HEAD").strip()
            desired = b"kind: ConfigMap\ndata: {phase: accepted}\n"
            (repository / "application.yaml").write_bytes(desired)
            ARGO.fixture_git(repository, "add", "--", "application.yaml")
            ARGO.fixture_git(repository, "commit", "-m", "Synthetic fixture accepted source")
            accepted = ARGO.fixture_git(repository, "rev-parse", "HEAD").strip()
            self.assertNotEqual(accepted, base)
            ARGO.prepare_bare_repository(repository, work / "source.git")

            class QuietHandler(http.server.SimpleHTTPRequestHandler):
                def log_message(self, *_args):
                    pass

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
                functools.partial(QuietHandler, directory=str(work)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                checkout = work / "readback"
                try:
                    ARGO.fixture_git(work, "clone", "--", f"http://127.0.0.1:{server.server_port}/source.git", checkout)
                except subprocess.CalledProcessError as error:
                    self.fail("prepared Git HTTP source could not be read: " + error.stderr.decode()[-512:])
                self.assertEqual(ARGO.fixture_git(checkout, "rev-parse", "HEAD").strip(), accepted)
                self.assertEqual((checkout / "application.yaml").read_bytes(), desired)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


class PreparationBoundaryTest(unittest.TestCase):
    def test_explicit_temporary_lab_config_and_admitted_tool_need_no_personal_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            tool, kubeconfig, image = work / "tool", work / "config", work / "image.tar"
            marker = work / "tool-invoked"
            tool.write_text("#!/bin/sh\nprintf invoked > " + shlex.quote(str(marker)) + "\n")
            tool.chmod(0o700)
            kubeconfig.write_text("synthetic input validation fixture; never read by a client\n")
            image.write_bytes(b"synthetic OCI wrapper; input validation never extracts it")
            values = dict(binary=str(tool), helm=str(tool), helm_digest=ARGO.file_digest(tool),
                application_oci=str(image), platform="linux/arm64", workdir=str(work / "new"),
                kubeconfig=str(kubeconfig), context="kind-cinderlock-portable", registry="127.0.0.1:5005",
                namespace="cinderlock-argocd-synthetic")
            selected_work, selected_image, tools = ARGO.validate_inputs(SimpleNamespace(**values))
            self.assertEqual(selected_work, work / "new")
            self.assertEqual(selected_image, image)
            self.assertEqual(tools["helm"], dict(path=str(tool), digest=values["helm_digest"]))
            self.assertFalse(selected_work.exists())
            self.assertFalse(marker.exists())

    def test_cli_requires_an_explicit_admitted_helm_digest(self):
        argv = []
        for name in ("binary", "helm", "application-oci", "platform", "workdir", "kubeconfig", "context", "registry"):
            argv += ["--" + name, "synthetic"]
        with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            ARGO.parser().parse_args(argv)

    def test_ambient_or_unadmitted_tools_are_refused_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            tool, kubeconfig, image = work / "helm", work / "config", work / "image.tar"
            marker = work / "tool-invoked"
            tool.write_text("#!/bin/sh\nprintf invoked > " + shlex.quote(str(marker)) + "\n")
            tool.chmod(0o700)
            kubeconfig.write_text("synthetic configuration; never read by a client\n")
            image.write_bytes(b"synthetic OCI wrapper; validation stops before extraction")
            values = dict(binary=str(tool), helm=str(tool), helm_digest=ARGO.file_digest(tool),
                application_oci=str(image), platform="linux/arm64",
                workdir=str(work / "new"), kubeconfig=str(kubeconfig), context="kind-cinderlock-synthetic",
                registry="127.0.0.1:5005", namespace="cinderlock-argocd-synthetic")
            for change, reason in ((dict(helm="helm"), "absolute"), (dict(binary="helm"), "absolute"),
                    (dict(helm_digest=None), "--helm-digest"), (dict(helm_digest=""), "helm-digest"),
                    (dict(helm_digest=values["helm_digest"][7:]), "helm-digest"),
                    (dict(helm_digest="SHA256:" + "a" * 64), "helm-digest"),
                    (dict(helm_digest="sha256:" + "A" * 64), "helm-digest"),
                    (dict(helm_digest="sha256:" + "g" * 64), "helm-digest"),
                    (dict(helm_digest="sha256:" + "a" * 63), "helm-digest"),
                    (dict(helm_digest="sha256:" + "a" * 65), "helm-digest"),
                    (dict(helm_digest=" " + values["helm_digest"]), "helm-digest"),
                    (dict(helm_digest=values["helm_digest"] + "\n"), "helm-digest"),
                    (dict(helm_digest=ARGO.sha256(b"different synthetic tool")), "admitted digest")):
                with self.subTest(change=change):
                    argv = [sys.executable, str(Path(ARGO.__file__))]
                    for key, value in dict(values, **change).items():
                        if value is not None:
                            argv += ["--" + key.replace("_", "-"), str(value)]
                    result = subprocess.run(argv, capture_output=True, text=True,
                                            env=dict(os.environ, PATH=str(work)), timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(reason, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertFalse((work / "new").exists())
                    self.assertFalse(marker.exists())

    def test_unsafe_targets_and_workdirs_fail_before_tools_or_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            marker = work / "tool-invoked"
            tool = work / "tool"
            tool.write_text("#!/bin/sh\nprintf invoked > " + shlex.quote(str(marker)) + "\n")
            tool.chmod(0o700)
            kubeconfig = work / "config"
            kubeconfig.write_text("synthetic input validation fixture; never read by a client\n")
            config_link = work / "config-link"
            config_link.symlink_to(kubeconfig)
            image = work / "image.tar"
            image.write_bytes(b"synthetic OCI wrapper; validation stops before extraction")
            existing = work / "existing"
            existing.mkdir()
            linked = work / "linked"
            linked.symlink_to(existing, target_is_directory=True)
            defaults = dict(binary=tool, helm=tool, helm_digest=ARGO.file_digest(tool), application_oci=image, platform="linux/amd64",
                workdir=work / "new", kubeconfig=kubeconfig, context="kind-cinderlock-synthetic",
                registry="127.0.0.1:5001/offline", namespace="cinderlock-argocd-synthetic")
            for changes, reason in ((dict(context="production"), "disposable"),
                    (dict(context="default"), "disposable"), (dict(context=""), "disposable"),
                    (dict(context="kind-cinderlock-"), "disposable"),
                    (dict(context="kind-cinderlock-Production"), "disposable"),
                    (dict(context="kind-cinderlock--lab"), "disposable"),
                    (dict(context="kind-cinderlock-lab-"), "disposable"),
                    (dict(context="kind-cinderlock-lab/other"), "disposable"),
                    (dict(context="kind-cinderlock-lab\n"), "disposable"),
                    (dict(kubeconfig="config"), "absolute"), (dict(kubeconfig=""), "absolute"),
                    (dict(kubeconfig=work / "missing-config"), "existing regular"),
                    (dict(kubeconfig=existing), "regular"), (dict(kubeconfig=config_link), "symlink"),
                    (dict(namespace="default"), "namespace"),
                    (dict(namespace=ARGO.CONTROLLER_NAMESPACE), "namespace"),
                    (dict(registry="registry.customer:5000/offline"), "loopback"),
                    (dict(registry="http://127.0.0.1:5001"), "loopback"),
                    (dict(workdir=existing), "new absolute"), (dict(workdir=linked / "new"), "symlink"),
                    (dict(workdir=work / ".." / "escape"), "new absolute")):
                with self.subTest(changes=changes):
                    values = dict(defaults, **changes)
                    argv = [sys.executable, str(Path(ARGO.__file__))]
                    for key, value in values.items():
                        argv += ["--" + key.replace("_", "-"), str(value)]
                    result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(reason, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertFalse(marker.exists())
                    self.assertFalse((work / "new").exists())


class ProposalAcceptanceTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        repository = self.work / "repository"
        repository.mkdir()
        ARGO.fixture_git(repository, "init", "--initial-branch=fixture", "--template=")
        source = repository / "application.yaml"
        source.write_bytes(b"kind: ConfigMap\ndata: {phase: base}\n")
        ARGO.fixture_git(repository, "add", "--", "application.yaml")
        ARGO.fixture_git(repository, "commit", "-m", "Synthetic fixture base")
        self.before = ARGO.repository_state(repository)
        self.base = self.before[0].decode()
        self.desired = b"kind: ConfigMap\ndata: {phase: accepted}\n"
        (self.work / "desired.yaml").write_bytes(self.desired)
        source.write_bytes(self.desired)
        patch = ARGO.fixture_git(repository, "diff", "--", "application.yaml")
        source.write_bytes(self.before[3])
        # This seam checks byte preservation; signature verification belongs to the real host CLI pass.
        (self.work / "release.cinder").write_bytes(b"synthetic bundle byte-identity fixture\n")
        self.bundle_file_digest = ARGO.file_digest(self.work / "release.cinder")
        self.bundle_digest = ARGO.sha256(b"synthetic verified index fixture")
        self.proposal = dict(owner="argocd", bundleDigest=self.bundle_digest, applicationAcceptance="not_established",
            source=dict(head=self.base, repository=str(repository), path="application.yaml", baseDigest=ARGO.sha256(self.before[3]),
                manifestDigest=ARGO.sha256(self.desired), patchDigest=ARGO.sha256(patch), patch=patch.decode()))
        self.save_proposal()

    def save_proposal(self):
        (self.work / "proposal.json").write_text(json.dumps(self.proposal))

    def accept(self):
        return ARGO.accept_proposal(self.work, self.base, self.bundle_digest, self.bundle_file_digest, self.before)

    def test_actual_patch_commits_export_and_preserves_bundle(self):
        accepted = self.accept()
        self.assertNotEqual(accepted, self.base)
        self.assertEqual(ARGO.fixture_git(self.work / "repository", "show", "HEAD:application.yaml"), self.desired)
        self.assertEqual(ARGO.fixture_git(self.work / "repository", "status", "--porcelain=v1"), b"")
        self.assertEqual(ARGO.file_digest(self.work / "release.cinder"), self.bundle_file_digest)
        ARGO.prepare_bare_repository(self.work / "repository", self.work / "source.git")
        packed = ARGO.source_archive(self.work / "source.git")
        archive = self.work / "source.tar.gz"
        archive.write_bytes(packed)
        destination = self.work / "readback"
        destination.mkdir()
        ARGO.extract_source(archive, destination)
        self.assertEqual(ARGO.fixture_git(destination / "source.git", "rev-parse", "HEAD").decode().strip(), accepted)
        self.assertEqual(ARGO.fixture_git(destination / "source.git", "show", "HEAD:application.yaml"), self.desired)

    def test_empty_or_mismatched_proposal_cannot_change_source(self):
        for field, value in (("patch", ""), ("head", "f" * 40), ("manifestDigest", ARGO.sha256(b"different")),
                             ("baseDigest", ARGO.sha256(b"different")), ("path", "other.yaml")):
            with self.subTest(field=field):
                original = self.proposal["source"][field]
                self.proposal["source"][field] = value
                self.save_proposal()
                with self.assertRaisesRegex(ValueError, "nonempty.*exact"):
                    self.accept()
                self.assertEqual(ARGO.repository_state(self.work / "repository"), self.before)
                self.assertFalse((self.work / "proposal.patch").exists())
                self.proposal["source"][field] = original

    def test_source_or_bundle_drift_is_refused_before_applying_patch(self):
        for selected in (self.work / "repository/.git/HEAD", self.work / "repository/.git/index",
                         self.work / "repository/application.yaml", self.work / "release.cinder"):
            with self.subTest(selected=selected.name):
                original = selected.read_bytes()
                # Append preserves a readable HEAD/index while still changing the exact source bytes.
                selected.write_bytes(original + b"\n")
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    self.accept()
                self.assertEqual(selected.read_bytes(), original + b"\n")
                self.assertFalse((self.work / "proposal.patch").exists())
                selected.write_bytes(original)


class ArchiveSafetyTest(unittest.TestCase):
    @staticmethod
    def tar_bytes(members):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for member, data in members:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return raw.getvalue()

    def test_bare_archive_refuses_escapes_links_special_members_and_bombs(self):
        regular = [(tarfile.TarInfo(name), b"synthetic\n") for name in
                   ("source.git/HEAD", "source.git/config", "source.git/info/refs")]
        for name, kind in (("../escape", tarfile.REGTYPE), ("/escape", tarfile.REGTYPE),
                ("source.git/../../escape", tarfile.REGTYPE), ("source.git//config", tarfile.REGTYPE),
                ("source.git/link", tarfile.SYMTYPE), ("source.git/link", tarfile.LNKTYPE),
                ("source.git/pipe", tarfile.FIFOTYPE), ("other.git/file", tarfile.REGTYPE),
                ("source.git/config", tarfile.REGTYPE)):
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary).resolve()
                member = tarfile.TarInfo(name)
                member.type, member.linkname = kind, "../../escape" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                archive = work / "source.gz"
                archive.write_bytes(gzip.compress(self.tar_bytes([*regular, (member, b"")])))
                destination = work / "out"
                destination.mkdir()
                with self.assertRaises(ValueError):
                    ARGO.extract_source(archive, destination)
                self.assertEqual(list(destination.iterdir()), [])
                self.assertFalse((work / "escape").exists())
        for data, reason in ((b"x" * ((512 << 10) + 1), "compressed"),
                             (gzip.compress(b"\0" * ((4 << 20) + 1)), "expanded")):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary).resolve()
                archive = work / "source.gz"
                archive.write_bytes(data)
                with self.assertRaisesRegex(ValueError, reason):
                    ARGO.extract_source(archive, work)

    def test_oci_members_and_image_selector_are_checked_without_a_tool(self):
        minimal = [(tarfile.TarInfo("oci-layout"), b'{"imageLayoutVersion":"1.0.0"}'),
                   (tarfile.TarInfo("index.json"), b'{"schemaVersion":2,"manifests":[]}')]
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            archive = work / "image.tar"
            archive.write_bytes(self.tar_bytes(minimal))
            ARGO.extract_oci(archive, work / "image")
            with self.assertRaisesRegex(ValueError, "ref 1"):
                ARGO.selected_manifest_digest(work / "image", "linux/amd64", work / "missing-ref.tar")
            with self.assertRaisesRegex(ValueError, "platform"):
                ARGO.selected_manifest_digest(work / "image", "amd64", work / "invalid-platform.tar")
            with self.assertRaises(FileNotFoundError):
                ARGO.extract_oci(work / "missing.tar", work / "unused")
        for name, kind in (("../escape", tarfile.REGTYPE), ("/index.json", tarfile.REGTYPE),
                           ("index.json", tarfile.SYMTYPE), ("blobs/sha256/link", tarfile.LNKTYPE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary).resolve()
                member = tarfile.TarInfo(name)
                member.type, member.linkname = kind, "../escape" if kind != tarfile.REGTYPE else ""
                archive = work / "image.tar"
                archive.write_bytes(self.tar_bytes([(member, b"")]))
                with self.assertRaises(ValueError):
                    ARGO.extract_oci(archive, work / "image")
                self.assertFalse((work / "escape").exists())

    def test_prefixed_oci_layout_selects_the_same_valid_manifest(self):
        config = b'{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}'
        config_digest = ARGO.sha256(config)
        manifest = json.dumps(dict(schemaVersion=2, mediaType="application/vnd.oci.image.manifest.v1+json",
            config=dict(mediaType="application/vnd.oci.image.config.v1+json", digest=config_digest, size=len(config)),
            layers=[]), separators=(",", ":")).encode()
        digest = ARGO.sha256(manifest)
        index = json.dumps(dict(schemaVersion=2, manifests=[dict(mediaType="application/vnd.oci.image.manifest.v1+json",
            digest=digest, size=len(manifest), annotations={"org.opencontainers.image.ref.name": "1"})])).encode()
        entries = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}', "index.json": index,
                   "blobs/sha256/" + digest[7:]: manifest, "blobs/sha256/" + config_digest[7:]: config}
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            archive = work / "image.tar"
            archive.write_bytes(self.tar_bytes([(tarfile.TarInfo("./" + name), data) for name, data in entries.items()]))
            ARGO.extract_oci(archive, work / "image")
            self.assertEqual(ARGO.selected_manifest_digest(work / "image", "linux/arm64", work / "normalized.tar"), digest)


class PlannedInputsTest(unittest.TestCase):
    def test_actual_helm_renders_only_supported_inventory_and_rejects_unpinned_image(self):
        helm = os.environ.get("CINDERLOCK_TEST_HELM", "")
        self.assertTrue(Path(helm).is_absolute() and os.access(helm, os.X_OK),
                        "CINDERLOCK_TEST_HELM must select an explicit admitted Helm executable")
        image = "127.0.0.1:5001/offline/application@sha256:" + "b" * 64
        with tempfile.TemporaryDirectory() as temporary:
            kubeconfig = Path(temporary) / "empty-kubeconfig"
            kubeconfig.touch(mode=0o600)
            environment = dict(os.environ, HELM_PLUGINS=temporary, HELM_CACHE_HOME=temporary,
                               HELM_CONFIG_HOME=temporary, HELM_DATA_HOME=temporary, KUBECONFIG=str(kubeconfig))
            argv = [helm, "template", "document-qa", str(ARGO.PROJECT / "examples/document-qa/argocd-chart"),
                    "--namespace", "cinderlock-argocd-synthetic", "--kubeconfig", str(kubeconfig), "--set-string"]
            rendered = subprocess.run([*argv, "image=" + image], capture_output=True, text=True, env=environment, timeout=30)
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            self.assertEqual(sorted(re.findall(r"(?m)^kind: (\S+)$", rendered.stdout)), ["ConfigMap", "Deployment", "Service"])
            self.assertEqual(re.findall(r'(?m)^\s+image: "([^"\n]+)"$', rendered.stdout), [image])
            self.assertNotRegex(rendered.stdout, r"(?m)\b(?:initContainers|ephemeralContainers|lifecycle|persistentVolumeClaim|helm\.sh/hook):")
            for unpinned in ("", "registry.customer/application:latest"):
                rejected = subprocess.run([*argv, "image=" + unpinned], capture_output=True, text=True, env=environment, timeout=30)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("image", rejected.stderr)

    def test_transport_and_application_keep_distinct_inventory_and_ownership(self):
        namespace, revision = "cinderlock-argocd-synthetic", "a" * 40
        image = "127.0.0.1:5001/offline/application@sha256:" + "b" * 64
        compressed = b"synthetic gzip bytes"
        transport = ARGO.source_transport(namespace, image, compressed)["items"]
        self.assertEqual([item["kind"] for item in transport], ["ConfigMap", "Pod", "Service"])
        for item in transport:
            self.assertNotIn("app.kubernetes.io/instance", item["metadata"]["labels"])
            self.assertNotIn("argocd.argoproj.io/tracking-id", item["metadata"].get("annotations", {}))
        self.assertEqual(base64.b64decode(transport[0]["binaryData"]["source.tar.gz"]), compressed)
        pod = transport[1]["spec"]
        self.assertIs(pod["automountServiceAccountToken"], False)
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertGreater(pod["securityContext"]["runAsUser"], 0)
        for container in [*pod["containers"], *pod["initContainers"]]:
            self.assertEqual(container["image"], image)
            self.assertEqual(set(container["resources"]["requests"]), {"cpu", "memory", "ephemeral-storage"})
            self.assertEqual(container["resources"]["requests"], container["resources"]["limits"])
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        app = ARGO.application(namespace, revision)
        self.assertEqual(app["spec"]["project"], namespace)
        self.assertEqual(app["spec"]["source"], dict(repoURL=f"http://source-server.{namespace}.svc.cluster.local:8000/source.git",
            targetRevision=revision, path=".", directory=dict(include="application.yaml")))
        self.assertEqual(app["spec"]["destination"], dict(server="https://kubernetes.default.svc", namespace=namespace))
        self.assertEqual(app["spec"]["syncPolicy"], dict(syncOptions=["ServerSideApply=true"]))
        self.assertNotIn("operation", app)
