#!/usr/bin/env python3
"""Real CLI integration against an explicitly provided disposable kind lab."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import tarfile
import uuid

PROJECT = Path(__file__).resolve().parents[2]
_reference_inputs_spec = importlib.util.spec_from_file_location(
    "cinderlock_reference_inputs", Path(__file__).with_name("reference_inputs.py"))
reference_inputs = importlib.util.module_from_spec(_reference_inputs_spec)
_reference_inputs_spec.loader.exec_module(reference_inputs)
API = reference_inputs.API
STORAGE_DOMAINS = reference_inputs.STORAGE_DOMAINS
helper_manifest_digest = reference_inputs.helper_manifest_digest
storage_capacities = reference_inputs.storage_capacities
storage_budgets = reference_inputs.storage_budgets
save = reference_inputs.save
header = reference_inputs.header
registry_container_observation = reference_inputs.registry_container_observation
registry_route = reference_inputs.registry_route
admit_registry_probe = reference_inputs.admit_registry_probe
workflow_checks = reference_inputs.workflow_checks


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

    job = staticmethod(reference_inputs.job)

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
        release = reference_inputs.release_declaration(number, self.args.platform, fixture)
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
