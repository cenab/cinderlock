#!/usr/bin/env python3
"""Real CLI integration against an explicitly provided disposable kind lab."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import tarfile
import uuid

PROJECT = Path(__file__).resolve().parents[2]
API = "cinderlock.dev/v1alpha1"
STORAGE_DOMAINS = ("operator", "registry", "runtime", "models", "indexes", "migrations", "backups")


def helper_manifest_digest(archive_path, platform):
    """Resolve the exact OCI ref `1`, using the same platform selection as lock."""
    index_types = {"application/vnd.oci.image.index.v1+json",
                   "application/vnd.docker.distribution.manifest.list.v2+json"}
    manifest_types = {"application/vnd.oci.image.manifest.v1+json",
                      "application/vnd.docker.distribution.manifest.v2+json"}
    parts = platform.split("/")
    if len(parts) not in (2, 3) or not all(parts):
        raise ValueError("helper platform must be os/architecture[/variant]")
    with tarfile.open(archive_path) as archive:
        def metadata(name, descriptor=None):
            member = archive.getmember(name)
            if not member.isfile() or not 0 <= member.size <= 8 << 20:
                raise ValueError("helper OCI metadata is not a bounded regular member")
            with archive.extractfile(member) as source:
                data = source.read((8 << 20) + 1)
            if len(data) != member.size:
                raise ValueError("helper OCI metadata size differs")
            if descriptor and (descriptor.get("size") != len(data) or
                               descriptor["digest"] != "sha256:" + hashlib.sha256(data).hexdigest()):
                raise ValueError("helper OCI descriptor digest/size differs from its bytes")
            value = json.loads(data)
            if not isinstance(value, dict) or value.get("schemaVersion") != 2:
                raise ValueError("helper OCI metadata needs schemaVersion 2")
            return value

        index = metadata("index.json")
        refs = [item for item in index.get("manifests", [])
                if item.get("annotations", {}).get("org.opencontainers.image.ref.name") == "1"]
        if len(refs) != 1:
            raise ValueError("helper OCI layout must have one unambiguous ref 1")
        descriptor = refs[0]

        def document(item):
            digest = item.get("digest", "")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                raise ValueError("helper OCI descriptor needs an exact SHA-256 digest")
            return metadata("blobs/sha256/" + digest[7:], item)

        value = document(descriptor)
        if descriptor.get("mediaType") in index_types:
            matches = [item for item in value.get("manifests", [])
                       if item.get("platform", {}).get("os") == parts[0]
                       and item.get("platform", {}).get("architecture") == parts[1]
                       and (len(parts) == 2 or item.get("platform", {}).get("variant") == parts[2])]
            if len(matches) != 1:
                raise ValueError("helper OCI platform is missing or ambiguous")
            descriptor = matches[0]
            document(descriptor)
        if descriptor.get("mediaType") not in manifest_types:
            raise ValueError("helper ref 1 must resolve to an image manifest")
        return descriptor["digest"]


def storage_capacities():
    observed = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return [dict(domain=domain, binding="synthetic-kind-shared-pool",
                 source="synthetic integration assertion; remote capacity was not measured",
                 availableBytes=8 << 30, retainedBytes=128 << 20,
                 observedAt=observed, status="asserted")
            for domain in STORAGE_DOMAINS if domain != "operator"]


def storage_budgets():
    # Signed, intentionally ample fixture declarations, not observed expansion.
    mebibytes = dict(operator=(64, 64), registry=(128, 128), runtime=(512, 256),
                    models=(8, 8), indexes=(32, 32), migrations=(32, 32), backups=(32, 32))
    return [dict(domain=domain, additionalBytes=mebibytes[domain][0] << 20,
                 temporaryBytes=mebibytes[domain][1] << 20) for domain in STORAGE_DOMAINS]


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def header(kind, **metadata):
    return dict(apiVersion=API, schemaVersion=1, kind=kind, metadata=metadata)


def registry_container_observation(parsed_docker_inspect, expected_name):
    try:
        if (not isinstance(expected_name, str) or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", expected_name) or
                not isinstance(parsed_docker_inspect, list) or len(parsed_docker_inspect) != 1 or
                not isinstance(parsed_docker_inspect[0], dict)):
            raise ValueError
        container = parsed_docker_inspect[0]
        container_id = container["Id"]
        state = container["State"]
        address = container["NetworkSettings"]["Networks"]["kind"]["IPAddress"]
        if (container["Name"] != "/" + expected_name or
                not isinstance(container_id, str) or not re.fullmatch(r"[0-9a-f]{64}", container_id) or
                state["Running"] is not True or state["Status"] != "running" or
                not isinstance(address, str)):
            raise ValueError
        ip = ipaddress.IPv4Address(address)
        if (ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast or
                address == "255.255.255.255"):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise ValueError("invalid registry container observation") from None
    return dict(name=expected_name, containerID=container_id, network="kind", address=address, port=5000)


def registry_route(namespace, observation):
    labels = {"cinderlock.dev/lab": "registry-probe"}
    return dict(apiVersion="v1", kind="List", items=[
        dict(apiVersion="v1", kind="Service",
            metadata=dict(name="registry-probe", namespace=namespace, labels=labels),
            spec=dict(ports=[dict(name="registry", protocol="TCP", port=5000, targetPort=5000)])),
        dict(apiVersion="discovery.k8s.io/v1", kind="EndpointSlice",
            metadata=dict(name="registry-probe", namespace=namespace,
                labels={**labels, "kubernetes.io/service-name": "registry-probe"}),
            addressType="IPv4", ports=[dict(name="registry", protocol="TCP", port=5000)],
            endpoints=[dict(addresses=[observation["address"]])]),
    ])


def admit_registry_probe(site_spec, policy_spec):
    for spec in (site_spec, policy_spec):
        actions = spec.setdefault("allowedActions", [])
        for action in ("job", "endpoint-probe", "endpoint-http"):
            if action not in actions:
                actions.append(action)
    hosts = site_spec.setdefault("allowedHosts", [])
    if "registry-probe" not in hosts:
        hosts.append("registry-probe")


def workflow_checks(number, fixture):
    names = (["health", "ingestion", "query", "persistence"] if number == 1
             else ["persistence", "health", "query", "ingestion"] if number == 2
             else ["persistence", "health", "query"])
    checks = [dict(id=name, type="job", domain="readiness" if name == "health" else "workflow",
        required=True, image="application", command=["python", "/app/app.py", "probe", "--base-url",
        "http://document-qa:8080", "--check", name], timeoutSeconds=90) for name in names]
    numeric = dict(id="numeric-observations", type="job", domain="workflow", required=True,
        image="application", command=["python", "/app/app.py", "observe", "--base-url", "http://document-qa:8080"],
        timeoutSeconds=90, observationContract=fixture.observation_contract())
    checks.append(numeric)
    if number == 2:
        checks.append(dict(numeric, id="numeric-budget-negative", required=False,
            command=[*numeric["command"], "--memory-limit-bytes", "0"],
            observationContract=fixture.observation_contract(memory_limit_bytes=0)))
    for check in checks:
        check["script"] = dict(
            inputs=["Locked application image, explicit probe argv, and declared synthetic fixture when present."],
            permissions=["Access the internal synthetic application HTTP endpoint; no Kubernetes API token."],
            sideEffects=["Upsert the fixed synthetic document." if check["id"] == "ingestion" else "Read synthetic application state without changing stored documents."],
            successChecks=[check["id"]], retry="manual")
        if check["domain"] == "workflow":
            check["fixtures"] = ["acceptance-fixture"]
            check["command"] += ["--fixture", "/cinderlock-fixtures/acceptance-fixture/document.json"]
    checks.append(dict(id="registry-route", type="endpoint", domain="readiness", required=True,
        url="http://registry-probe:5000/v2/", method="GET", expectedStatus=200, timeoutSeconds=30))
    return checks


class Lab:
    def __init__(self, args):
        self.args = args
        self.work = Path(args.workdir).resolve()
        self.work.mkdir(mode=0o700, parents=True)
        self.tmp = self.work / "tmp"
        self.tmp.mkdir(mode=0o700)
        self.env = dict(os.environ, TMPDIR=str(self.tmp))
        self.helper_digest = helper_manifest_digest(args.helper_oci, args.platform)
        self.namespace = "cinderlock-it-" + uuid.uuid4().hex[:10]
        self.counter = 0
        self.site = self.work / "site.json"
        self.receipts = []

    def command(self, argv, expected=0):
        result = subprocess.run([str(x) for x in argv], cwd=PROJECT,
                                capture_output=True, text=True, timeout=1200, env=self.env)
        self.counter += 1
        stem = self.work / "receipts" / str(self.counter)
        save(stem.with_suffix(".json"), dict(command=[str(x) for x in argv],
             code=result.returncode, stdout=result.stdout, stderr=result.stderr))
        if result.returncode != expected:
            raise RuntimeError(f"Command failed ({result.returncode}); receipt: {stem}.json\n{result.stderr}")
        return result.stdout

    def cli(self, *args, expected=0):
        raw = self.command([self.args.binary, "--output", "json", "--no-interactive",
                            "--state", self.work / "state", "--cache", self.work / "cache",
                            *args], expected)
        value = json.loads(raw)
        return value.get("result", value)

    def kube(self, *args):
        return self.command(["kubectl", "--kubeconfig", self.args.kubeconfig,
                             "--context", self.args.context, *args])

    def json_observation(self, argv, maximum):
        completed = subprocess.run([str(arg) for arg in argv], cwd=PROJECT,
                                   capture_output=True, timeout=30, env=self.env)
        if completed.returncode != 0 or completed.stderr or len(completed.stdout) > maximum:
            raise RuntimeError("lab JSON observation failed or exceeded its bound")

        def unique(pairs):
            value = dict(pairs)
            if len(value) != len(pairs):
                raise ValueError
            return value

        try:
            value = json.loads(completed.stdout, object_pairs_hook=unique)
        except (ValueError, UnicodeError, RecursionError):
            raise RuntimeError("lab JSON observation is malformed") from None
        return value, "sha256:" + hashlib.sha256(completed.stdout).hexdigest()

    def prepare(self):
        inspected, _ = self.json_observation(["docker", "inspect", "--type", "container", "--", self.args.registry_container], 1 << 20)
        registry = registry_container_observation(inspected, self.args.registry_container)
        save(self.work / "registry-observation.json", registry)
        self.kube("create", "namespace", self.namespace)
        route = self.work / "registry-route.json"
        save(route, registry_route(self.namespace, registry))
        self.kube("create", "-f", route)
        self.cli("trust", "keygen", "--private", self.work / "release.key",
                 "--public", self.work / "release.pub")
        self.cli("trust", "keygen", "--private", self.work / "approval.key",
                 "--public", self.work / "approval.pub")
        self.cli("trust", "keygen", "--private", self.work / "policy.key",
                 "--public", self.work / "policy.pub")
        self.cli("trust", "init", "--application", "document-qa", "--key-id", "release",
                 "--public", self.work / "release.pub", "--out", self.work / "candidate.json")
        self.cli("trust", "propose-update", self.work / "candidate.json", "--application", "document-qa",
                 "--role", "approval", "--key-id", "approval", "--public", self.work / "approval.pub",
                 "--out", self.work / "trust-with-approval.json")
        self.cli("trust", "propose-update", self.work / "trust-with-approval.json", "--application", "*",
                 "--channel", "*", "--role", "policy", "--key-id", "policy-admin",
                 "--public", self.work / "policy.pub", "--out", self.work / "trust-with-admin.json")
        policy = json.loads((self.work / "trust-with-admin.json").read_text())
        actions = ["import", "seed", "job", "backup", "migrate", "helm", "restart", "uninstall",
                   "registry-http", "support-export", "gitops-observe", "storage-assertions",
                   "admission-dry-run"]
        policy["spec"]["allowedActions"] = actions
        helm = Path(shutil.which("helm")).resolve()
        site = header("Site", name=self.namespace)
        site["spec"] = dict(kubeconfig=str(Path(self.args.kubeconfig).resolve()), context=self.args.context,
            namespace=self.namespace, releaseName="document-qa", registry=self.args.registry,
            registryPlainHTTP=True, trustPolicy=str(self.work / "trust.json"),
            helmPath=str(helm), helmDigest="sha256:" + hashlib.sha256(helm.read_bytes()).hexdigest(),
            helperImage=self.helper_digest, profile="kubernetes-cpu-lab",
            storageProfile="peaks-v1", storageOperatorPath=str(self.work),
            storageCapacities=storage_capacities(), admissionDryRun=True,
            values=dict(data=dict(capacity="192Mi")),
            stateDir=str(self.work / "state"), allowedActions=actions,
            dataRevision="schema-v1", backupRef="/data/before-v2.sqlite")
        admit_registry_probe(site["spec"], policy["spec"])
        save(self.work / "trust.json", policy)
        save(self.site, site)
        preview = self.cli("trust", "admit-policy", "--site", self.site)
        assert preview["admitted"] is False
        admitted = self.cli("trust", "admit-policy", "--site", self.site,
                            "--approved-digest", preview["policyDigest"])
        assert admitted["admitted"] is True

    def refresh_storage(self):
        site = json.loads(self.site.read_text())
        site["spec"]["storageCapacities"] = storage_capacities()
        save(self.site, site)

    def rotate_policy(self):
        self.cli("trust", "keygen", "--private", self.work / "release-next.key",
                 "--public", self.work / "release-next.pub")
        site = json.loads(self.site.read_text())
        candidate = self.work / "policy-next-candidate.json"
        self.cli("trust", "propose-update", site["spec"]["trustPolicy"], "--application", "document-qa",
                 "--role", "release", "--key-id", "release-next", "--public", self.work / "release-next.pub",
                 "--out", candidate)
        packet = self.work / "policy-update.json"
        self.cli("trust", "update-sign", "--site", self.site, "--candidate", candidate,
                 "--key", self.work / "policy.key", "--key-id", "policy-admin",
                 "--decision-reference", "synthetic-integration-rotation", "--out", packet)
        preview = self.cli("trust", "update-preview", packet, "--site", self.site)
        admitted_path = self.work / "admitted-policy-next.json"
        receipt = self.cli("trust", "update-admit", packet, "--site", self.site,
                           "--approved-digest", preview["packetDigest"], "--out", admitted_path)
        assert receipt["admitted"] is True
        site["spec"]["trustPolicy"] = str(admitted_path)
        save(self.site, site)

    def intake(self, bundle):
        trust = json.loads(self.site.read_text())["spec"]["trustPolicy"]
        manifest, receipt = self.work / "intake.json", self.work / "custody-receipt.json"
        self.cli("bundle", "intake-manifest", bundle, "--trust", trust, "--out", manifest)
        self.cli("trust", "keygen", "--private", self.work / "custody.key",
                 "--public", self.work / "custody.pub")
        expires = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat().replace("+00:00", "Z")
        policy = header("CustodyPolicy")
        policy["keys"] = [dict(id="test-custodian", publicKey=(self.work / "custody.pub").read_text(),
            custodians=["synthetic-intake"], sites=[self.namespace], applications=["document-qa"],
            profiles=["kubernetes-cpu-lab"], expiresAt=expires)]
        keys = self.work / "custody-policy.json"
        save(keys, policy)
        common = ["--bundle", bundle, "--trust", trust, "--manifest", manifest,
                  "--keys", keys, "--previous-head", "genesis"]
        self.cli("intake", "sign-receipt", *common, "--key", self.work / "custody.key",
                 "--key-id", "test-custodian", "--custodian", "synthetic-intake", "--site", self.namespace,
                 "--expires", expires, "--out", receipt)
        verify = ["intake", "verify-receipt", receipt, *common, "--head-file", self.work / "custody-head.json"]
        result = self.cli(*verify)
        assert result["anchored"] is True and result["signature"] == "verified", result
        replay = self.cli(*verify, expected=12)
        assert replay["code"] == 12, replay

    @staticmethod
    def job(name, kind, argv, after=None):
        effects = {
            "quiesce": "Set synthetic application maintenance mode.",
            "backup": "Create an instance-bound SQLite backup and digest manifest at the declared output path.",
            "migrate": "Change the SQLite schema and commit its operation ledger in the same transaction.",
            "resume-writes": "Clear synthetic application maintenance mode.",
            "restore": "Replace synthetic fixture data from its approved test backup; retain maintenance mode.",
        }
        return dict(id=name, type=kind, image="application", command=["python", "/app/app.py", *argv],
            pvc="document-qa-data", mountPath="/data", idempotent=True,
            dependsOn=[after] if after else [], timeoutSeconds=120,
            script=dict(inputs=["Locked application image, explicit argv, operation identity, and synthetic SQLite instance on /data."],
                permissions=["Read and write the synthetic database and backup files on document-qa-data; no Kubernetes API token."],
                sideEffects=[effects[argv[0]]], successChecks=["persistence", "query"], retry="retry-safe"))

    def release(self, number):
        directory = self.work / f"v{number}"
        directory.mkdir()
        for name, archive in [("image", self.args.application_oci), ("helper", self.args.helper_oci)]:
            destination = directory / name
            destination.mkdir()
            with tarfile.open(archive) as source:
                source.extractall(destination, filter="data")
        for name in ["chart", "models", "fixtures"]:
            shutil.copytree(PROJECT / "examples" / "document-qa" / name, directory / name)
        chart = directory / "chart" / "Chart.yaml"
        chart.write_text(chart.read_text().replace("version: 0.1.0", f"version: 0.{number}.0")
                         .replace('appVersion: "1.0.0"', f'appVersion: "{number}.0.0"'))
        self.command(["helm", "package", directory / "chart", "--destination", directory])
        model_spec = importlib.util.spec_from_file_location("fixture", PROJECT / "examples/document-qa/app.py")
        fixture = importlib.util.module_from_spec(model_spec)
        model_spec.loader.exec_module(fixture)
        (directory / "models" / ".fixture-ready.json").write_text(
            json.dumps(fixture.models(directory / "models"), sort_keys=True))
        values = dict(appVersion=f"{number}.0.0", schemaTarget=1 if number == 1 else 2)
        if number > 1:
            values["models"] = dict(existingClaim="document-qa-model-v2")
        save(directory / "values.json", values)
        checks = workflow_checks(number, fixture)
        fixture_seed = dict(id="acceptance-fixtures", type="seed", asset="acceptance-fixture",
            pvc=f"document-qa-fixture-v{number}", mountPath="/fixtures", storageBytes=16 << 20,
            idempotent=True, dependsOn=["images"], timeoutSeconds=120)
        operations = [dict(id="images", type="import", idempotent=True), fixture_seed]
        if number == 2:
            operations += [dict(id="models", type="seed", asset="model",
                pvc="document-qa-model-v2", mountPath="/models", storageBytes=128 << 20,
                idempotent=True, dependsOn=["acceptance-fixtures"], timeoutSeconds=120)]
        if number > 1:
            operations += [self.job("quiesce", "job", ["quiesce"], "models" if number == 2 else "acceptance-fixtures"),
                self.job("backup", "backup", ["backup", "--out", f"/data/before-v{number}.sqlite"], "quiesce")]
        if number == 2:
            migration = self.job("schema", "migrate", ["migrate", "--to", "2", "--operation-id", "schema-v1-v2"], "backup")
            migration["reconcileCommand"] = ["python", "/app/app.py", "reconcile", "--operation-id", "schema-v1-v2"]
            operations += [migration]
        operations += [dict(id="deploy", type="helm", dependsOn=[operations[-1]["id"]], timeoutSeconds=180)]
        if number == 3:
            operations += [dict(id="synthetic-data-loss", type="job", image="application", pvc="document-qa-data",
                mountPath="/data", command=["python", "-c", "import sqlite3; c=sqlite3.connect('/data/app.sqlite'); c.execute(\"DELETE FROM documents WHERE id='cinderlock-fixture-redwood'\"); c.commit()"],
                dependsOn=["deploy"], idempotent=True, timeoutSeconds=90, destructive=True,
                script=dict(inputs=["Locked application image and mounted synthetic SQLite fixture database."],
                    permissions=["Delete the fixed synthetic document on document-qa-data; no Kubernetes API token."],
                    sideEffects=["Delete cinderlock-fixture-redwood to exercise a real missing-document acceptance failure."],
                    successChecks=["persistence", "query"], retry="retry-safe"))]
        if number > 1:
            operations += [self.job("writes", "job", ["resume-writes"], operations[-1]["id"])]
        operations += [dict(id="restart", type="restart", service="document-qa",
                           dependsOn=[operations[-1]["id"]], timeoutSeconds=180)]
        recovery_seed = dict(fixture_seed, id="recovery-fixtures",
            pvc=f"document-qa-recovery-fixture-v{number}", dependsOn=[])
        recovery = dict(id="repair", toRelease=f"{number}.0.0", requiresBackup=number > 1,
            operations=[recovery_seed, dict(id="repair-restart", type="restart", service="document-qa",
                dependsOn=["recovery-fixtures"], timeoutSeconds=180)], checks=checks)
        if number == 3:
            recovery.update(id="restore-synthetic-data", dataRevision="schema-v2", destructive=True,
                operations=[recovery_seed, self.job("recovery-quiesce", "job", ["quiesce"], "recovery-fixtures"),
                    self.job("restore-fixture", "job", ["restore", "--backup", "/data/before-v3.sqlite", "--authorize-test-restore"], "recovery-quiesce"),
                    self.job("recovery-writes", "job", ["resume-writes"], "restore-fixture"),
                    dict(id="recovery-restart", type="restart", service="document-qa", dependsOn=["recovery-writes"], timeoutSeconds=180)])
        transition = dict(id=f"to-v{number}", fromRelease="install" if number == 1 else f"{number-1}.0.0",
            operations=[op["id"] for op in operations], recovery=recovery["id"])
        if number > 1:
            transition.update(fromDataRevision=f"schema-v{1 if number == 2 else 2}", toDataRevision="schema-v2")
        release = header("Release", application="document-qa", version=f"{number}.0.0", channel="stable", sequence=number)
        release["spec"] = dict(profile="kubernetes-cpu-lab", storageBudgets=storage_budgets(), deployment=dict(type="helm",
            chart=f"./document-qa-0.{number}.0.tgz", values=["./values.json"],
            configuration=dict(version=1, fields=[
                dict(path="image", owner="generated", type="string", required=True),
                dict(path="appVersion", owner="vendor", type="string", required=True),
                dict(path="schemaTarget", owner="vendor", type="integer", required=True),
                dict(path="imagePullPolicy", owner="vendor", type="string", required=True),
                dict(path="data.capacity", owner="site", type="string", required=True),
                dict(path="data.existingClaim", owner="vendor", type="string", required=True),
                dict(path="data.storageClass", owner="site", type="string", required=True),
                dict(path="models", owner="vendor", type="object", required=True)]),
            imageBindings=[dict(asset="application", valuesPath="image")]),
            assets=[dict(id=name, type="image", source=f"oci:./{source}#1", platform=self.args.platform)
                    for name, source in [("application", "image"), ("helper", "helper")]]
                   + [dict(id="model", type="model-tree", source="./models", license="Apache-2.0"),
                      dict(id="acceptance-fixture", type="file-tree", source="./fixtures", license="Apache-2.0")],
            aiProfile=dict(modelAsset="model", runtimeAsset="application"), operations=operations,
            transitions=[transition], checks=checks, requiredChecks=[c["id"] for c in checks if c["required"]], recovery=[recovery])
        save(directory / "release.json", release)
        self.cli("release", "lock", directory / "release.json", "--out", directory / "release.lock.json")
        locked = json.loads((directory / "release.lock.json").read_text())
        helpers = [asset for asset in locked["assets"] if asset["id"] == "helper"]
        assert len(helpers) == 1 and helpers[0]["digest"] == self.helper_digest, helpers
        bundle = self.work / f"v{number}.cinder"
        self.cli("bundle", "build", directory / "release.lock.json", "--key", self.work / "release.key",
                 "--key-id", "release", "--out", bundle)
        return bundle

    def worker_pod(self, source, run_id):
        job = json.loads(self.kube("-n", self.namespace, "get", "job", source["jobName"], "-o", "json"))
        assert job["metadata"]["uid"] == source["jobUID"], "worker Job UID changed"
        assert job["metadata"]["labels"]["cinderlock.dev/run"] == run_id, "worker Job run changed"
        assert job["metadata"]["annotations"]["cinderlock.dev/recipe-digest"] == source["recipeDigest"], "worker recipe changed"
        assert any(c["type"] == "Complete" and c["status"] == "True" for c in job["status"]["conditions"]), "worker Job is not complete"
        pods = json.loads(self.kube("-n", self.namespace, "get", "pods", "-l", "job-name=" + source["jobName"], "-o", "json"))["items"]
        assert len(pods) == 1, "worker Job has no unique original Pod"
        pod = pods[0]
        assert pod["metadata"]["uid"] and pod["status"]["phase"] == "Succeeded", "worker Pod did not complete successfully"
        controllers = [owner for owner in pod["metadata"]["ownerReferences"] if owner.get("controller")]
        assert len(controllers) == 1 and all(controllers[0][key] == value for key, value in
            dict(apiVersion="batch/v1", kind="Job", name=source["jobName"], uid=source["jobUID"]).items()), "worker Pod owner changed"
        return job, pod

    def observation_output(self, source, run_id):
        _, pod = self.worker_pod(source, run_id)
        identity = (source["podName"], source["podUID"])
        assert (pod["metadata"]["name"], pod["metadata"]["uid"]) == identity, "numeric Pod identity changed"
        output = self.kube("-n", self.namespace, "logs", "pod/" + source["podName"], "-c", "operation")
        _, pod = self.worker_pod(source, run_id)
        assert (pod["metadata"]["name"], pod["metadata"]["uid"]) == identity, "numeric Pod identity changed"
        assert 0 < len(output.encode()) <= 64 << 10, "numeric output exceeds the declared document bound"
        assert source["outputDigest"] == "sha256:" + hashlib.sha256(output.encode()).hexdigest(), "numeric original output digest changed"
        return json.loads(output)

    def endpoint_observation(self, plan, result):
        check = next(check for check in plan["checks"] if check["id"] == "registry-route")
        assert check["required"] and check["id"] in plan["requiredChecks"], "registry route is not required"
        outcome = next(check for check in result["checks"] if check["id"] == "registry-route")
        assert outcome["required"] and outcome["domain"] == "readiness" and outcome["status"] == "pass", "registry prerequisite did not pass"
        events = self.cli("run", "events", result["runID"])
        step = "@check/registry-route"
        bindings = [event for event in events if event["type"] == "worker_bound" and event["data"]["stepID"] == step]
        assert len(bindings) == 1, "registry route lacks one original public worker binding"
        binding = bindings[0]["data"]
        assert binding["role"] == step and binding["attempt"] == 1 and binding["uid"], "registry worker binding changed"
        assert outcome["evidence"] == "job/" + binding["name"], "registry result references another worker"
        completed = [event for event in events if event["type"] == "operation_outcome" and event["data"]["stepID"] == step]
        assert len(completed) == 1 and completed[0]["data"]["state"] == "complete", "registry route has no completed journal outcome"
        assert bindings[0]["seq"] < completed[0]["seq"], "registry completion preceded its worker binding"
        mutations = {operation["id"] for operation in plan["operations"] if operation["type"] != "import"}
        mutation_intents = [event for event in events if event["type"] == "operation_intent" and event["data"]["stepID"] in mutations]
        assert mutation_intents and completed[0]["seq"] < min(event["seq"] for event in mutation_intents), "registry prerequisite followed application work"
        source = dict(jobName=binding["name"], jobUID=binding["uid"], recipeDigest=binding["recipeDigest"])
        expected = dict(image=self.args.registry.rstrip("/") + "/helper@" + self.helper_digest,
            command=["/usr/local/bin/cinderlock", "helper", "endpoint-probe"], args=["--url", check["url"],
            "--method", "GET", "--expected-status", "200", "--timeout-seconds", "30", "--allow-http"])

        def original():
            job, pod = self.worker_pod(source, result["runID"])
            for spec in [job["spec"]["template"]["spec"], pod["spec"]]:
                assert len(spec["containers"]) == 1, "registry worker container set changed"
                container = spec["containers"][0]
                assert container["name"] == "operation" and all(container[key] == value for key, value in expected.items()), "registry fixed helper recipe changed"
            statuses = pod["status"]["containerStatuses"]
            assert len(statuses) == 1 and statuses[0]["name"] == "operation" and statuses[0]["state"]["terminated"]["exitCode"] == 0, "registry worker did not exit zero"
            return pod["metadata"]["name"], pod["metadata"]["uid"]

        name, uid = original()
        output, digest = self.json_observation(["kubectl", "--kubeconfig", self.args.kubeconfig, "--context", self.args.context,
            "-n", self.namespace, "logs", "pod/" + name, "-c", "operation"], 4096)
        assert original() == (name, uid), "registry Pod identity changed during capture"
        assert output == dict(apiVersion=API, kind="CommandResult", command="cinderlock helper endpoint-probe",
            result=dict(status=200, response="observed", authorization="not_supplied")), "registry helper did not emit its bounded status observation"
        assert type(output["result"]["status"]) is int, "registry observed status is not an integer"
        return dict(jobName=source["jobName"], jobUID=source["jobUID"], recipeDigest=source["recipeDigest"],
            podName=name, podUID=uid, exitCode=0, outputDigest=digest, observation=output["result"])

    def observations(self, plan, result, missing=False):
        for check in plan["checks"]:
            contract = check.get("observationContract")
            if contract is None:
                continue
            negative = check["id"] == "numeric-budget-negative"
            required = not negative
            assert check["required"] is required, "numeric negative control must remain optional"
            assert (check["id"] in plan["requiredChecks"]) is required, "numeric requiredChecks changed"
            outcome = next(item for item in result["checks"] if item["id"] == check["id"])
            assert outcome["required"] is required, "numeric result required scope changed"
            assert outcome["status"] == ("fail" if missing or negative else "pass"), "numeric outcome differs from actual fixture/budget case"
            observed = outcome["observations"]
            assert observed["basis"] == "application_reported" and observed["contract"] == contract, "numeric declaration differs"
            source = observed["source"]
            assert all(source[key] for key in ["jobName", "jobUID", "podName", "podUID"]), "numeric source identity missing"
            assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", source[key]) for key in ["recipeDigest", "outputDigest"]), "numeric source digest missing"
            assert outcome["evidence"] == "job/" + source["jobName"], "numeric evidence points at another worker"
            report = observed["report"]
            assert report == self.observation_output(source, result["runID"]), "numeric recorded samples differ from original output"
            assert report["profile"] == contract["profile"] and report["device"] == "cpu" and report["mode"] == "client-tracemalloc", "numeric measurement scope changed"
            assert report["runtime"].startswith("python-test-client-") and report["warmCold"] == "unknown" and report["concurrency"] == 1, "numeric runtime/cache scope changed"
            assert [sample["index"] for sample in report["samples"]] == list(range(1, contract["sampleCount"] + 1)), "numeric samples omitted or reordered"
            for sample in report["samples"]:
                assert [(metric["name"], metric["unit"]) for metric in sample["metrics"]] == [(bound["name"], bound["unit"]) for bound in contract["metrics"]], "numeric metrics omitted or reordered"
                for metric, bound in zip(sample["metrics"], contract["metrics"], strict=True):
                    value = metric["value"]
                    assert type(value) is int, "numeric value is not an integer"
                    if bound["name"] == "fixture-match":
                        assert value == (0 if missing else 1), "numeric fixture assertion differs"
                    elif bound["name"] == "client-traced-peak":
                        assert value > 0, "numeric allocation was not measured"
                    if negative and bound["name"] == "client-traced-peak":
                        assert bound["max"] == 0 and value > bound["max"], "negative allocation budget did not fail against measured output"
                    elif not (missing and bound["name"] == "fixture-match"):
                        assert bound["min"] <= value <= bound["max"], "numeric sample missed its ordinary budget"

    def execute(self, bundle, prefix, expected=0, recovery=None):
        self.refresh_storage()
        plan = self.work / f"{prefix}-plan.json"
        if recovery:
            self.cli("run", "recovery-plan", recovery, "--recovery", "restore-synthetic-data", "--out", plan)
        else:
            self.cli("run", "plan", bundle, "--site", self.site, "--out", plan)
        planned = json.loads(plan.read_text())
        assert planned["storage"]["profile"] == "peaks-v1" and planned["storage"]["executable"], planned
        authorization = self.work / f"{prefix}-authorization.json"
        self.cli("run", "authorize", plan, "--key", self.work / "approval.key", "--key-id", "approval", "--out", authorization)
        if prefix == "v2":
            self.rotate_policy()
            rejected = self.cli("run", "apply", plan, "--authorization", authorization, expected=11)
            assert rejected["kind"] == "Error" and rejected["code"] == 11, rejected
            plan, authorization = self.work / "v2-replanned.json", self.work / "v2-reauthorized.json"
            self.refresh_storage()
            self.cli("run", "plan", bundle, "--site", self.site, "--out", plan)
            self.cli("run", "authorize", plan, "--key", self.work / "approval.key",
                     "--key-id", "approval", "--out", authorization)
        if recovery:
            result = self.cli("run", "recover", recovery, "--plan", plan, "--authorization", authorization, expected=expected)
        else:
            result = self.cli("run", "apply", plan, "--authorization", authorization, expected=expected)
        recorded = self.cli("run", "report", result["runID"], "--format", "json")
        assert recorded == result, "public CLI report differs from returned run evidence"
        planned = json.loads(plan.read_text())
        save(self.work / f"{prefix}-endpoint.json", self.endpoint_observation(planned, recorded))
        self.observations(planned, recorded, missing=prefix == "v3")
        self.receipts.append(result)
        save(self.work / f"{prefix}-result.json", result)
        return result

    def test(self):
        self.prepare()
        for number in [1, 2, 3]:
            if number == 3:
                site = json.loads(self.site.read_text())
                site["spec"].update(dataRevision="schema-v2", backupRef="/data/before-v3.sqlite")
                save(self.site, site)
            bundle = self.release(number)
            if number == 1:
                self.intake(bundle)
            result = self.execute(bundle, f"v{number}", expected=15 if number == 3 else 0)
            if number < 3:
                assert result["state"] == "succeeded" and result["acceptance"] == "pass", result
                assert all(c["status"] == "pass" for c in result["checks"] if c["required"]), result
                if number == 2:
                    negative = next(c for c in result["checks"] if c["id"] == "numeric-budget-negative")
                    assert not negative["required"] and negative["status"] == "fail", negative
            else:
                assert result["acceptance"] != "pass" and any(c["id"] == "persistence" and c["status"] == "fail" for c in result["checks"]), result
                # The failure must come from the actual missing document, not orchestration.
                assert all(step["status"] == "pass" for step in result["steps"]), result
                failed = next(check for check in result["checks"] if check["id"] == "persistence")
                assert failed["evidence"].startswith("job/"), failed
                logs = self.kube("-n", self.namespace, "logs", failed["evidence"])
                assert "probe HTTP status 404" in logs, logs
                recovered = self.execute(bundle, "recovery", recovery=result["runID"])
                assert recovered["state"] == "recovered", recovered
                assert recovered["sourceRun"] == result["runID"], recovered
                assert all(c["status"] == "pass" for c in recovered["checks"]), recovered
                original = self.cli("run", "status", result["runID"])
                assert original["result"]["acceptance"] != "pass", original
                self.cli("run", "report", recovered["runID"], "--format", "html", "--out", self.work / "recovery.html")
                self.cli("run", "events", recovered["runID"])
        save(self.work / "summary.json", dict(namespace=self.namespace, results=self.receipts,
             gpu="not_tested", physicalIsolation="not_established", productionRecovery="not_qualified",
             remoteStorageCapacity="synthetic_assertions_not_measured", numericMemoryScope="test_client_python_traced_allocation_only"))
        print(f"CLI install, migration, persistence, numeric observations, failed acceptance and synthetic restore passed: {self.work}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ["binary", "kubeconfig", "context", "registry", "registry-container", "workdir", "application-oci", "helper-oci", "platform"]:
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args()
    if not args.context.startswith("kind-cinderlock-") or not args.registry.startswith("127.0.0.1:"):
        parser.error("This fixture only targets an explicit kind-cinderlock-* context and loopback test registry")
    args.binary = str(Path(args.binary).resolve())
    lab = Lab(args)
    try:
        lab.test()
    finally:
        print(f"Disposable namespace retained for inspection: {lab.namespace}; use explicit kubeconfig/context to remove it.")


if __name__ == "__main__":
    main()
