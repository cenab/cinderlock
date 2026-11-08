#!/usr/bin/env python3
"""Build a pinned Helm source with patched dependencies into private local paths."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

MODULE_DIR = Path(__file__).resolve().parent
PROJECT = MODULE_DIR.parents[1]
HELM_VERSION = "v4.3.1"
HELM_COMMIT = "c0d08d0d6d9424d4a14febb5e8a3e51b0dd00dff"
HELM_SUM = "h1:UndCoLe9UPmNoL7IvWzaUXveL7T5t/ijoorEmgJdI9g="
HELM_MOD_SUM = "h1:Z663D/wNQG1UsG3X7svSEBPvosFVel4SIw4YIMZwmuY="
GO_VERSION = "go1.27.3"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return "sha256:" + result.hexdigest()


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024 * 1024:
        raise ValueError("Expected a bounded regular file")


def run(argv, directory, environment, log):
    with log.open("ab") as output:
        result = subprocess.run(argv, cwd=directory, env=environment,
                                stdout=subprocess.PIPE, stderr=output,
                                timeout=1200, check=False)
        if result.returncode:
            output.write(result.stdout)
            raise RuntimeError(f"Approved preparation command failed; private log: {log}")
    if len(result.stdout) > 1024 * 1024:
        raise ValueError("Preparation metadata exceeds its limit")
    return result.stdout


def environment():
    result = dict(os.environ)
    for key in ["GOROOT", "GOOS", "GOARCH", "GOAMD64", "GOARM", "GOARM64", "GOMIPS",
                "GOMIPS64", "GOPPC64", "GORISCV64", "GOEXPERIMENT"]:
        result.pop(key, None)
    result.update(GOTOOLCHAIN="local", GOENV="off", GOWORK="off", GOFLAGS="")
    return result


def public_tree(source, destination):
    count = total = 0
    for parent, directories, files in os.walk(source, followlinks=False):
        for name in directories + files:
            path = Path(parent) / name
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            regular(path)
            count += 1
            total += info.st_size
            if count > 100000 or total > 8 * 1024 * 1024 * 1024:
                raise ValueError("Vendored notice/source tree exceeds supported bounds")
    shutil.copytree(source, destination)


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    path.chmod(0o600)


def prepare(args):
    go = Path(args.go).absolute()
    out = Path(args.out).absolute()
    notices = Path(args.notices).absolute()
    regular(go)
    if out.exists() or out.is_symlink() or notices.exists() or notices.is_symlink():
        raise FileExistsError("Helm executable and notice output paths must be new")
    for value in [out.parent, notices.parent]:
        value.mkdir(parents=True, exist_ok=True, mode=0o700)
    work_parent = PROJECT / ".local/tools/builds"
    work_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    work = Path(tempfile.mkdtemp(prefix="helm-", dir=work_parent))
    log = work / "preparation.log"
    log.touch(mode=0o600)
    env = environment()
    try:
        details = json.loads(run([str(go), "env", "-json", "GOVERSION", "GOROOT", "GOOS", "GOARCH"], work, env, log))
        if details["GOVERSION"] != GO_VERSION:
            raise ValueError(f"This preparation recipe requires exactly {GO_VERSION}")
        module = work / "module"
        module.mkdir()
        for name in ["go.mod", "go.sum"]:
            regular(MODULE_DIR / name)
            shutil.copyfile(MODULE_DIR / name, module / name)
        before = {name: digest(module / name) for name in ["go.mod", "go.sum"]}
        print("Verify pinned Helm modules and prepare the vendor tree.", file=sys.stderr)
        origin = json.loads(run([str(go), "mod", "download", "-json", "helm.sh/helm/v4@" + HELM_VERSION], module, env, log))
        if (origin["Sum"] != HELM_SUM or origin["GoModSum"] != HELM_MOD_SUM
                or origin["Origin"]["Hash"] != HELM_COMMIT
                or origin["Origin"]["URL"] != "https://github.com/helm/helm"):
            raise ValueError("Helm source checksum/tag identity differs from the admitted recipe")
        run([str(go), "mod", "verify"], module, env, log)
        run([str(go), "mod", "vendor"], module, env, log)
        if before != {name: digest(module / name) for name in before}:
            raise ValueError("Vendoring changed the admitted Helm tool module")
        offline = dict(env)
        offline.update(GOPROXY="off", GOSUMDB="off", GONOPROXY="none", GONOSUMDB="none",
                       GOPRIVATE="", GOMODCACHE=str(work / "empty-module-cache"),
                       GOPATH=str(work / "gopath"), GOCACHE=str(work / "build-cache"),
                       CGO_ENABLED="0", HOME=str(work), KUBECONFIG=str(work / "no-kubeconfig"))
        binary = work / "helm"
        flags = " ".join(["-X helm.sh/helm/v4/internal/version.version=" + HELM_VERSION,
                          "-X helm.sh/helm/v4/internal/version.metadata=cinderlock.1",
                          "-X helm.sh/helm/v4/internal/version.gitCommit=" + HELM_COMMIT,
                          "-X helm.sh/helm/v4/internal/version.gitTreeState=modified-dependencies"])
        print("Compile the vendored Helm tool with Go acquisition disabled.", file=sys.stderr)
        run([str(go), "build", "-mod=vendor", "-trimpath", "-buildvcs=false",
             "-ldflags", flags, "-o", str(binary), "helm.sh/helm/v4/cmd/helm"], module, offline, log)
        print("Scan the resulting Helm executable before publication.", file=sys.stderr)
        scan = run([str(go), "run", "golang.org/x/vuln/cmd/govulncheck@v1.9.0",
                    "-mode=binary", str(binary)], module, env, log)
        buildinfo = run([str(go), "version", "-m", str(binary)], module, env, log).decode()
        materials = work / "notices"
        materials.mkdir()
        shutil.copyfile(module / "vendor/helm.sh/helm/v4/LICENSE", materials / "LICENSE")
        shutil.copyfile(Path(details["GOROOT"]) / "LICENSE", materials / "GO-LICENSE")
        public_tree(module / "vendor", materials / "vendor")
        for name in before:
            shutil.copyfile(module / name, materials / name)
        (materials / "govulncheck.txt").write_bytes(scan)
        (materials / "build-info.txt").write_text("helm\t" + details["GOVERSION"] + "\n" + "\n".join(buildinfo.splitlines()[1:]) + "\n")
        record = dict(apiVersion="cinderlock.dev/v1alpha1", kind="HelmPreparation",
                      source=dict(module="helm.sh/helm/v4", version=HELM_VERSION,
                                  commit=HELM_COMMIT, sum=HELM_SUM, goModSum=HELM_MOD_SUM),
                      toolchain=dict(go=GO_VERSION, os=details["GOOS"], arch=details["GOARCH"],
                                     executableDigest=digest(go)),
                      moduleDigests=before, executableDigest=digest(binary),
                      noticeScope="operator-supplied pinned Helm and complete Go-vendored build source/license tree; not a legal completeness attestation",
                      buildScope="native CGO-disabled vendored compilation with empty module cache; no cluster operations",
                      scanScope="govulncheck v1.9.0 binary analysis at preparation time; no reachable finding, not a perpetual vulnerability clearance")
        save(materials / "provenance.json", record)
        # Reserve the new notice destination; a preexisting directory is never replaced.
        notices.mkdir(mode=0o700)
        published = False
        try:
            for child in materials.iterdir():
                shutil.move(str(child), notices / child.name)
            with tempfile.NamedTemporaryFile(prefix=".helm-", dir=out.parent, delete=False) as target:
                temporary = Path(target.name)
                try:
                    os.fchmod(target.fileno(), 0o700)
                    with binary.open("rb") as source:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
                    target.flush()
                    os.fsync(target.fileno())
                    os.link(temporary, out)
                    published = True
                finally:
                    temporary.unlink(missing_ok=True)
        finally:
            if not published:
                shutil.rmtree(notices)
        shutil.rmtree(work)
        return dict(executable=str(out), notices=str(notices), **record)
    except Exception:
        print(f"Preparation failed; private staging retained: {work}", file=sys.stderr)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", required=True, help="Exact admitted Go 1.27.3 executable")
    parser.add_argument("--out", required=True, help="New Helm executable path")
    parser.add_argument("--notices", required=True, help="New admitted notice/source directory")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(prepare(args), sort_keys=True, indent=2))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
