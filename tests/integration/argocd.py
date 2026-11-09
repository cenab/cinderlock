#!/usr/bin/env python3
"""Prepare private Argo directory qualification inputs without applying them."""

import argparse
import base64
import gzip
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import uuid

PROJECT = Path(__file__).resolve().parents[2]
CONTROLLER_NAMESPACE = "cinderlock-argocd-lab"
PROFILE = "argocd-directory-v1"
ACTIONS = ["import", "gitops-stage", "gitops-observe", "registry-http"]

_reference_inputs_spec = importlib.util.spec_from_file_location(
    "cinderlock_reference_inputs", Path(__file__).with_name("reference_inputs.py"))
reference_inputs = importlib.util.module_from_spec(_reference_inputs_spec)
_reference_inputs_spec.loader.exec_module(reference_inputs)
header, save = reference_inputs.header, reference_inputs.save


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def file_digest(filename):
    with Path(filename).open("rb") as source:
        return "sha256:" + hashlib.file_digest(source, "sha256").hexdigest()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    for flag in ("binary", "helm", "helm-digest", "application-oci", "platform", "workdir", "kubeconfig", "context", "registry"):
        result.add_argument("--" + flag, required=True)
    result.add_argument("--namespace", default="cinderlock-argocd-" + uuid.uuid4().hex[:10])
    return result


def validate_inputs(args):
    # Select the lab before resolving tools or creating any output.
    if not re.fullmatch(r"kind-cinderlock-[a-z0-9]+(?:-[a-z0-9]+)*", args.context):
        raise ValueError("context must explicitly select a disposable kind-cinderlock-* lab")
    if (not re.fullmatch(r"cinderlock-argocd-[a-z0-9][a-z0-9-]{0,40}[a-z0-9]", args.namespace)
            or args.namespace == CONTROLLER_NAMESPACE):
        raise ValueError("target namespace must be a fresh cinderlock-argocd-* namespace, separate from the controller")
    registry = re.fullmatch(r"(?:127\.0\.0\.1|localhost|\[::1\]):([1-9][0-9]{0,4})(?:/[a-z0-9]+(?:[._/-][a-z0-9]+)*)?", args.registry)
    if not registry or int(registry[1]) > 65535:
        raise ValueError("registry must explicitly select a loopback host and port, without credentials, tags, or a scheme")
    work = Path(args.workdir)
    if not work.is_absolute() or ".." in work.parts or work.exists() or work.is_symlink():
        raise ValueError("workdir must be a new absolute private directory")
    if not work.parent.is_dir() or any(parent.is_symlink() for parent in work.parents):
        raise ValueError("workdir needs an existing parent without symlink ancestors")
    kubeconfig = Path(args.kubeconfig)
    if not kubeconfig.is_absolute() or not kubeconfig.is_file() or kubeconfig.resolve() != kubeconfig:
        raise ValueError("kubeconfig must select an absolute existing regular file without symlinks")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.helm_digest):
        raise ValueError("helm-digest must be sha256:<64 lowercase hex> from an independent admitted tool record")
    if not re.fullmatch(r"linux/[a-z0-9_]+(?:/[a-z0-9_]+)?", args.platform):
        raise ValueError("platform must explicitly select linux/architecture[/variant]")
    image = Path(args.application_oci).resolve(strict=True)
    if not image.is_file() or not 0 < image.stat().st_size <= 512 << 20:
        raise ValueError("application OCI archive must be a bounded regular file")
    tools = {}
    for name in ("binary", "helm"):
        executable = Path(getattr(args, name))
        if not executable.is_absolute():
            raise ValueError(name + " must select an explicit absolute executable path")
        resolved = executable.resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise ValueError(name + " must select a regular executable file")
        tools[name] = dict(path=str(resolved), digest=file_digest(resolved))
    if tools["helm"]["digest"] != args.helm_digest:
        raise ValueError("Helm bytes differ from the explicit admitted digest")
    return work, image, tools


def fixture_git(directory, *args):
    executable = shutil.which("git")
    if not executable:
        raise RuntimeError("Git is required for the private source fixture")
    command = [executable, "--no-pager", "--no-optional-locks", "--no-replace-objects",
               "-c", "user.name=SYNTHETIC Cinderlock fixture",
               "-c", "user.email=synthetic-fixture@example.invalid",
               "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull,
               "-c", "core.fsmonitor=false", "-c", "core.attributesFile=" + os.devnull,
               "-c", "core.autocrlf=false", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
               *map(str, args)]
    environment = dict(PATH=str(Path(executable).parent), GIT_CONFIG_NOSYSTEM="1",
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM="1",
                       GIT_TERMINAL_PROMPT="0", LANG="C", LC_ALL="C")
    return subprocess.run(command, cwd=directory, env=environment, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout


def prepare_bare_repository(repository, destination):
    fixture_git(repository, "clone", "--bare", "--no-hardlinks", "--template=", "--", repository, destination)
    fixture_git(destination, "config", "--remove-section", "remote.origin")
    fixture_git(destination, "update-server-info")


def extract_oci(archive_path, destination):
    if not 0 < archive_path.stat().st_size <= 512 << 20:
        raise ValueError("OCI archive exceeds the local fixture bound")
    seen, total = set(), 0
    # shortcut: plain OCI tar wrappers only; add a bounded decoder if an admitted fixture needs outer compression.
    with tarfile.open(archive_path, "r:") as archive:
        for count, member in enumerate(archive, 1):
            if count > 4096:
                raise ValueError("OCI archive has too many members")
            name = member.name.removeprefix("./").rstrip("/")
            if member.isdir() and (member.name in (".", "./") or name in ("blobs", "blobs/sha256")):
                continue
            if (not member.isfile() or member.issparse()
                    or not re.fullmatch(r"(?:index\.json|oci-layout|blobs/sha256/[0-9a-f]{64})", name)
                    or name in seen or not 0 <= member.size <= 512 << 20):
                raise ValueError("OCI archive needs unique bounded regular layout members without links or path escapes")
            seen.add(name)
            total += member.size
            if len(seen) > 4096 or total > 512 << 20:
                raise ValueError("OCI archive exceeds the local fixture bound")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with archive.extractfile(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, 1 << 20)
            target.chmod(0o600)
    if not {"index.json", "oci-layout"} <= seen:
        raise ValueError("OCI archive is missing its layout or index")


def extract_source(archive_path, destination):
    """The same bounded extractor runs in the source-server init container."""
    import gzip
    import io
    from pathlib import Path, PurePosixPath
    import tarfile

    archive_path, destination = Path(archive_path), Path(destination)
    if archive_path.stat().st_size > 512 << 10:
        raise ValueError("source archive exceeds compressed bound")
    with gzip.open(archive_path, "rb") as compressed:
        raw = compressed.read((4 << 20) + 1)
    if len(raw) > 4 << 20:
        raise ValueError("source archive exceeds expanded bound")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members, seen = [], set()
        for member in archive:
            name = PurePosixPath(member.name)
            if (not member.isfile() or member.issparse() or member.pax_headers or member.size < 0
                    or name.is_absolute() or ".." in name.parts or "\\" in member.name
                    or len(name.parts) < 2 or name.parts[0] != "source.git"
                    or str(name) != member.name or member.name in seen):
                raise ValueError("source archive needs unique regular source.git members without links or path escapes")
            members.append(member)
            seen.add(member.name)
            if len(members) > 4096:
                raise ValueError("source archive has too many members")
        if not {"source.git/HEAD", "source.git/config", "source.git/info/refs"} <= seen:
            raise ValueError("source archive is missing bare HTTP metadata")
        if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
            raise ValueError("source extraction needs an empty real directory")
        for member in members:
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with archive.extractfile(member) as source, target.open("xb") as output:
                data = source.read((4 << 20) + 1)
                if len(data) != member.size or len(data) > 4 << 20:
                    raise ValueError("source archive member exceeds its bound")
                output.write(data)
            target.chmod(0o600)
        # Bare clones pack refs; Git still needs the empty refs directory after transport.
        (destination / "source.git/refs").mkdir(mode=0o700, exist_ok=True)


def selected_manifest_digest(layout, platform, normalized_archive):
    # The house selector expects canonical names; extraction accepts a leading ./.
    with tarfile.open(normalized_archive, "x", format=tarfile.USTAR_FORMAT) as archive:
        for entry in sorted(layout.rglob("*")):
            if entry.is_file():
                member = tarfile.TarInfo(entry.relative_to(layout).as_posix())
                member.size, member.mode = entry.stat().st_size, 0o600
                with entry.open("rb") as source:
                    archive.addfile(member, source)
    return reference_inputs.helper_manifest_digest(normalized_archive, platform)


def source_archive(bare):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        total = 0
        for entry in sorted(bare.rglob("*")):
            if entry.is_symlink() or not (entry.is_dir() or entry.is_file()):
                raise ValueError("bare source contains a link or special file")
            if entry.is_dir():
                continue
            total += entry.stat().st_size
            if total > 4 << 20:
                raise ValueError("bare source exceeds expanded bound")
            member = tarfile.TarInfo("source.git/" + entry.relative_to(bare).as_posix())
            data = entry.read_bytes()
            member.size, member.mode = len(data), 0o600
            archive.addfile(member, io.BytesIO(data))
            if raw.tell() > 4 << 20:
                raise ValueError("bare source exceeds expanded bound")
    compressed = gzip.compress(raw.getvalue(), mtime=0)
    if len(raw.getvalue()) > 4 << 20 or len(compressed) > 512 << 10:
        raise ValueError("bare source archive exceeds transport bounds")
    return compressed


def source_transport(namespace, image, compressed):
    labels = {"cinderlock.dev/lab-transport": "source"}
    metadata = dict(name="source-server", namespace=namespace, labels=labels)
    security = dict(allowPrivilegeEscalation=False, readOnlyRootFilesystem=True,
                    capabilities=dict(drop=["ALL"]))
    resources = dict(requests={"cpu": "100m", "memory": "64Mi", "ephemeral-storage": "32Mi"},
                     limits={"cpu": "100m", "memory": "64Mi", "ephemeral-storage": "32Mi"})
    container = dict(image=image, imagePullPolicy="IfNotPresent", resources=resources, securityContext=security)
    extractor = inspect.getsource(extract_source) + "\nextract_source('/archive/source.tar.gz', '/srv')\n"
    return dict(apiVersion="v1", kind="List", items=[
        dict(apiVersion="v1", kind="ConfigMap", metadata=metadata,
             binaryData={"source.tar.gz": base64.b64encode(compressed).decode("ascii")}),
        dict(apiVersion="v1", kind="Pod", metadata=metadata, spec=dict(
            automountServiceAccountToken=False,
            securityContext=dict(runAsNonRoot=True, runAsUser=10001, runAsGroup=10001,
                                 fsGroup=10001, seccompProfile=dict(type="RuntimeDefault")),
            initContainers=[dict(container, name="extract", command=["python", "-c", extractor],
                volumeMounts=[dict(name="archive", mountPath="/archive", readOnly=True), dict(name="source", mountPath="/srv")])],
            containers=[dict(container, name="http", command=["python", "-m", "http.server"],
                args=["8000", "--bind", "0.0.0.0", "--directory", "/srv"],
                ports=[dict(name="http", containerPort=8000, protocol="TCP")],
                readinessProbe=dict(httpGet=dict(path="/source.git/HEAD", port="http"), periodSeconds=1),
                volumeMounts=[dict(name="source", mountPath="/srv", readOnly=True)])],
            volumes=[dict(name="archive", configMap=dict(name="source-server", defaultMode=0o444)),
                     dict(name="source", emptyDir=dict(sizeLimit="8Mi"))])),
        dict(apiVersion="v1", kind="Service", metadata=metadata,
             spec=dict(type="ClusterIP", selector=labels,
                       ports=[dict(name="http", protocol="TCP", port=8000, targetPort=8000)]))])


def application(namespace, revision):
    return dict(apiVersion="argoproj.io/v1alpha1", kind="Application",
        metadata=dict(name=namespace, namespace=CONTROLLER_NAMESPACE), spec=dict(project=namespace,
            source=dict(repoURL=f"http://source-server.{namespace}.svc.cluster.local:8000/source.git",
                targetRevision=revision, path=".", directory=dict(include="application.yaml")),
            destination=dict(server="https://kubernetes.default.svc", namespace=namespace),
            syncPolicy=dict(syncOptions=["ServerSideApply=true"])))


def release_declaration(base, platform):
    release = header("Release", application="document-qa", version="1.0.0", channel="stable", sequence=1)
    check = dict(id="health", type="job", domain="workflow", required=True, image="application",
        command=["python", "/app/app.py", "probe", "--base-url", "http://document-qa:8080", "--check", "health"],
        timeoutSeconds=60, script=dict(inputs=["Locked application image and internal synthetic health endpoint."],
            permissions=["HTTP health read only; no Kubernetes API token."], sideEffects=["Read synthetic health only."],
            successChecks=["health"], retry="manual", resources=dict(cpuMillis=100, memoryBytes=64 << 20,
                ephemeralStorageBytes=32 << 20, temporaryBytes=8 << 20, gpuCount=0)))
    release["spec"] = dict(profile=PROFILE, deployment=dict(type="gitops", chart="./document-qa-argocd-0.1.0.tgz",
        gitOps=dict(owner="argocd", revision=base, path="application.yaml"),
        imageBindings=[dict(asset="application", valuesPath="image")], allowedKinds=["Deployment", "Service", "ConfigMap"]),
        assets=[dict(id="application", type="image", source="oci:./image#1", platform=platform)],
        operations=[dict(id="source", type="gitops")],
        transitions=[dict(id="install", fromRelease="install", operations=["source"], recovery="manual-source")],
        checks=[check], requiredChecks=["health"], recovery=[dict(id="manual-source", toRelease="1.0.0",
            operations=[], checks=[])])
    return release


def repository_state(repository):
    return (fixture_git(repository, "rev-parse", "HEAD").strip(), (repository / ".git/HEAD").read_bytes(),
            (repository / ".git/index").read_bytes(), (repository / "application.yaml").read_bytes(),
            fixture_git(repository, "status", "--porcelain=v1"))


def accept_proposal(work, base, bundle_digest, bundle_file_digest, before):
    repository, bundle = work / "repository", work / "release.cinder"
    desired = (work / "desired.yaml").read_bytes()
    proposal = json.loads((work / "proposal.json").read_text())
    source = proposal["source"]
    patch = source["patch"].encode("utf-8")
    if (not patch or proposal["owner"] != "argocd" or proposal["bundleDigest"] != bundle_digest
            or proposal["applicationAcceptance"] != "not_established" or source["head"] != base
            or source["repository"] != str(repository) or source["path"] != "application.yaml"
            or source["baseDigest"] != sha256(before[3]) or source["manifestDigest"] != sha256(desired)
            or source["patchDigest"] != sha256(patch) or desired == before[3]):
        raise ValueError("proposal must be nonempty and bind the exact base, bundle, source, and exported bytes")
    if repository_state(repository) != before or file_digest(bundle) != bundle_file_digest:
        raise ValueError("source HEAD/index/file or signed bundle changed before fixture acceptance")
    patch_path = work / "proposal.patch"
    patch_path.write_bytes(patch)
    patch_path.chmod(0o600)
    fixture_git(repository, "apply", "--check", "--", patch_path)
    fixture_git(repository, "apply", "--", patch_path)
    if ((repository / "application.yaml").read_bytes() != desired
            or fixture_git(repository, "diff", "--name-only") != b"application.yaml\n"):
        raise ValueError("proposal did not change only the owned application.yaml to the exact export")
    fixture_git(repository, "add", "--", "application.yaml")
    fixture_git(repository, "commit", "-m", "Synthetic fixture accepted source")
    accepted = fixture_git(repository, "rev-parse", "HEAD").decode().strip()
    if (accepted == base or fixture_git(repository, "status", "--porcelain=v1")
            or fixture_git(repository, "show", "HEAD:application.yaml") != desired
            or file_digest(bundle) != bundle_file_digest):
        raise ValueError("accepted source or unchanged signed bundle invariant failed")
    return accepted


def prepare(args):
    work, image, tools = validate_inputs(args)
    work.mkdir(mode=0o700)
    for name in ("material", "keys", "state", "cache", "tmp", "home", "repository", "source-readback"):
        (work / name).mkdir(mode=0o700)
    environment = dict(os.environ, TMPDIR=str(work / "tmp"),
                       KUBECONFIG=args.kubeconfig, HELM_PLUGINS=str(work / "home/plugins"),
                       HELM_CONFIG_HOME=str(work / "home/helm"), HELM_CACHE_HOME=str(work / "home/cache"),
                       HELM_DATA_HOME=str(work / "home/data"))
    cli = [tools["binary"]["path"], "--output", "json", "--no-interactive", "--state", str(work / "state"),
           "--cache", str(work / "cache")]
    commands = []

    def command(argv):
        argv = list(map(str, argv))
        tool = next(record for record in tools.values() if record["path"] == argv[0])
        if file_digest(argv[0]) != tool["digest"]:
            raise ValueError("selected tool bytes changed")
        completed = subprocess.run(argv, cwd=work, env=environment, capture_output=True, text=True, timeout=300)
        commands.append(dict(argv=argv, exitCode=completed.returncode))
        save(work / "commands.json", commands)
        if completed.returncode:
            raise RuntimeError(f"host preparation command failed ({completed.returncode}): {argv}\n{completed.stderr}")
        if argv[0] == cli[0]:
            value = json.loads(completed.stdout)
            return value.get("result", value)

    extract_oci(image, work / "material/image")
    selected = selected_manifest_digest(work / "material/image", args.platform, work / "tmp/selected-oci.tar")
    fixture_git(work / "repository", "init", "--object-format=sha1", "--initial-branch=fixture", "--template=")
    (work / "repository/application.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: synthetic-source-base\ndata:\n  phase: base-A\n")
    fixture_git(work / "repository", "add", "--", "application.yaml")
    fixture_git(work / "repository", "commit", "-m", "Synthetic fixture base")
    base = fixture_git(work / "repository", "rev-parse", "HEAD").decode().strip()
    for role in ("release", "approval"):
        command([*cli, "trust", "keygen", "--private", work / f"keys/{role}.key", "--public", work / f"keys/{role}.pub"])
    command([*cli, "trust", "init", "--application", "document-qa", "--key-id", "release",
             "--public", work / "keys/release.pub", "--out", work / "policy-candidate.json"])
    command([*cli, "trust", "propose-update", work / "policy-candidate.json", "--application", "document-qa",
             "--role", "approval", "--key-id", "approval", "--public", work / "keys/approval.pub", "--out", work / "trust.json"])
    policy = json.loads((work / "trust.json").read_text())
    policy["spec"]["allowedActions"] = ACTIONS
    save(work / "trust.json", policy)
    policy_digest = command([*cli, "trust", "validate", work / "trust.json"])["digest"]
    site = header("Site", name=args.namespace)
    site["spec"] = dict(kubeconfig=args.kubeconfig, context=args.context, namespace=args.namespace,
        releaseName="document-qa", registry=args.registry, registryPlainHTTP=True, trustPolicy=str(work / "trust.json"),
        helmPath=tools["helm"]["path"], helmDigest=tools["helm"]["digest"], profile=PROFILE,
        stateDir=str(work / "state"), allowedActions=ACTIONS)
    save(work / "site.yaml", site)
    site_path = work / "site.yaml"
    command([tools["helm"]["path"], "package", PROJECT / "examples/document-qa/argocd-chart", "--destination", work / "material",
             "--kubeconfig", args.kubeconfig, "--kube-context", args.context])
    save(work / "material/release.json", release_declaration(base, args.platform))
    command([*cli, "release", "lock", work / "material/release.json", "--out", work / "material/release.lock.json"])
    locked = json.loads((work / "material/release.lock.json").read_text())
    if [asset["digest"] for asset in locked["assets"] if asset["id"] == "application"] != [selected]:
        raise ValueError("locked application differs from the selected OCI platform/ref 1")
    bundle = work / "release.cinder"
    command([*cli, "bundle", "build", work / "material/release.lock.json", "--key", work / "keys/release.key", "--key-id", "release", "--out", bundle])
    bundle_digest = command([*cli, "bundle", "verify", bundle, "--trust", work / "trust.json"])["digest"]
    bundle_file_digest = file_digest(bundle)
    command([*cli, "gitops", "export", bundle, "--site", site_path, "--out", work / "desired.yaml"])
    before = repository_state(work / "repository")
    command([*cli, "gitops", "propose", bundle, "--site", site_path, "--repository", work / "repository", "--head", base,
             "--path", "application.yaml", "--manifest", work / "desired.yaml", "--approved-manifest-digest", file_digest(work / "desired.yaml"),
             "--out", work / "proposal.json"])
    accepted = accept_proposal(work, base, bundle_digest, bundle_file_digest, before)
    prepare_bare_repository(work / "repository", work / "source.git")
    compressed = source_archive(work / "source.git")
    archive_path = work / "source.tar.gz"
    archive_path.write_bytes(compressed)
    archive_path.chmod(0o600)
    extract_source(archive_path, work / "source-readback")
    if (fixture_git(work / "source-readback/source.git", "rev-parse", "HEAD").decode().strip() != accepted
            or fixture_git(work / "source-readback/source.git", "show", "HEAD:application.yaml") != (work / "desired.yaml").read_bytes()):
        raise ValueError("archived source does not retain the accepted commit and exported bytes")
    imported_image = args.registry + "/application@" + selected
    save(work / "source-transport.json", source_transport(args.namespace, imported_image, compressed))
    app = application(args.namespace, accepted)
    save(work / "application.json", app)
    bound_site = str(work / "site-bound.yaml")
    kube = ["kubectl", "--kubeconfig", args.kubeconfig, "--context", args.context]
    future = [dict(step="create fresh namespace", argv=[*kube, "create", "namespace", args.namespace]),
        dict(step="observe target, then write site-bound.yaml with actual pins", argv=[*cli, "target", "inspect", "--site", str(site_path), "--out", str(work / "target.json")]),
        dict(step="review and admit policy after binding Site", argv=[*cli, "trust", "admit-policy", "--site", bound_site, "--approved-digest", policy_digest]),
        dict(step="plan image staging", argv=[*cli, "gitops", "artifacts-plan", str(bundle), "--site", bound_site, "--out", str(work / "artifacts-plan.json")]),
        dict(step="review and authorize image-only plan", argv=[*cli, "run", "authorize", str(work / "artifacts-plan.json"), "--key", str(work / "keys/approval.key"), "--key-id", "approval", "--out", str(work / "artifacts-authorization.json")]),
        dict(step="stage image", argv=[*cli, "run", "apply", str(work / "artifacts-plan.json"), "--authorization", str(work / "artifacts-authorization.json")]),
        dict(step="create unowned source transport after staging", argv=[*kube, "create", "-f", str(work / "source-transport.json")]),
        dict(step="create Application only after source HTTP readback; lab operator separately requests sync", argv=[*kube, "create", "-f", str(work / "application.json")])]
    save(work / "future-argv.json", future)
    receipt = header("ArgoQualificationInputs", name=args.namespace)
    receipt.update(sourceBase=base, acceptedRevision=accepted, repository=str(work / "repository"),
        project=dict(namespace=CONTROLLER_NAMESPACE, name=app["spec"]["project"]),
        repositoryURL=app["spec"]["source"]["repoURL"], applicationOCI=str(image), applicationOCIDigest=file_digest(image),
        platform=args.platform, selectedImageDigest=selected, importedImage=imported_image, tools=tools,
        bundleDigest=bundle_digest, bundleFileDigest=bundle_file_digest,
        inputs={name: dict(path=str(work / name), digest=file_digest(work / name)) for name in (
            "site.yaml", "trust.json", "material/release.json", "material/release.lock.json", "material/document-qa-argocd-0.1.0.tgz",
            "desired.yaml", "proposal.json", "source.tar.gz", "source-transport.json", "application.json", "future-argv.json")},
        liveQualification="pending", applicationAcceptance="not_established",
        recoveryBoundary="Manual source reversion requires separate review; ephemeral SQLite data has no recovery claim.",
        remainingDependency="Select the final observer binary and bind real target/Application identities and original notBefore; host preparation is not live observer qualification")
    save(work / "receipt.json", receipt)
    return work / "receipt.json"


def main():
    arguments = parser()
    args = arguments.parse_args()
    try:
        print(prepare(args))
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError, tarfile.TarError) as error:
        arguments.exit(1, f"preparation refused: {error}\n")


if __name__ == "__main__":
    main()
