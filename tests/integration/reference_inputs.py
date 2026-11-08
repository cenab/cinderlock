"""Reference declarations and input helpers for the integration labs."""

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
import tarfile

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
            successChecks=[check["id"]], retry="manual",
            resources=dict(cpuMillis=250, memoryBytes=256 << 20, ephemeralStorageBytes=64 << 20,
                temporaryBytes=16 << 20, gpuCount=0))
        if check["domain"] == "workflow":
            check["fixtures"] = ["acceptance-fixture"]
            check["command"] += ["--fixture", "/cinderlock-fixtures/acceptance-fixture/document.json"]
    checks.append(dict(id="registry-route", type="endpoint", domain="readiness", required=True,
        url="http://registry-probe:5000/v2/", method="GET", expectedStatus=200, timeoutSeconds=30))
    return checks


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
            sideEffects=[effects[argv[0]]], successChecks=["persistence", "query"], retry="retry-safe",
            resources=dict(cpuMillis=250, memoryBytes=256 << 20, ephemeralStorageBytes=64 << 20,
                temporaryBytes=16 << 20, gpuCount=0)))


def release_declaration(number, platform, fixture):
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
        operations += [job("quiesce", "job", ["quiesce"], "models" if number == 2 else "acceptance-fixtures"),
            job("backup", "backup", ["backup", "--out", f"/data/before-v{number}.sqlite"], "quiesce")]
    if number == 2:
        migration = job("schema", "migrate", ["migrate", "--to", "2", "--operation-id", "schema-v1-v2"], "backup")
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
                successChecks=["persistence", "query"], retry="retry-safe",
                resources=dict(cpuMillis=250, memoryBytes=256 << 20, ephemeralStorageBytes=64 << 20,
                    temporaryBytes=16 << 20, gpuCount=0)))]
    if number > 1:
        operations += [job("writes", "job", ["resume-writes"], operations[-1]["id"])]
    operations += [dict(id="restart", type="restart", service="document-qa",
                       dependsOn=[operations[-1]["id"]], timeoutSeconds=180)]
    recovery_seed = dict(fixture_seed, id="recovery-fixtures",
        pvc=f"document-qa-recovery-fixture-v{number}", dependsOn=[])
    recovery = dict(id="repair", toRelease=f"{number}.0.0", requiresBackup=number > 1,
        operations=[recovery_seed, dict(id="repair-restart", type="restart", service="document-qa",
            dependsOn=["recovery-fixtures"], timeoutSeconds=180)], checks=checks)
    if number == 3:
        recovery.update(id="restore-synthetic-data", dataRevision="schema-v2", destructive=True,
            operations=[recovery_seed, job("recovery-quiesce", "job", ["quiesce"], "recovery-fixtures"),
                job("restore-fixture", "job", ["restore", "--backup", "/data/before-v3.sqlite", "--authorize-test-restore"], "recovery-quiesce"),
                job("recovery-writes", "job", ["resume-writes"], "restore-fixture"),
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
        assets=[dict(id=name, type="image", source=f"oci:./{source}#1", platform=platform)
                for name, source in [("application", "image"), ("helper", "helper")]]
               + [dict(id="model", type="model-tree", source="./models", license="Apache-2.0"),
                  dict(id="acceptance-fixture", type="file-tree", source="./fixtures", license="Apache-2.0")],
        aiProfile=dict(modelAsset="model", runtimeAsset="application"), operations=operations,
        transitions=[transition], checks=checks, requiredChecks=[c["id"] for c in checks if c["required"]], recovery=[recovery])
    return release
