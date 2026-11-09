"""Persistent GitOps fixture recipes; these are synthetic lab procedures."""

import copy
import inspect
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise RuntimeError("Kubernetes credential requests cannot follow redirects")


def controlled_pods(request, namespace, deployment):
    selector = deployment["spec"]["selector"]["matchLabels"]
    pods = request("GET", "/api/v1/namespaces/" + namespace + "/pods?limit=257")
    assert not pods.get("metadata", {}).get("continue") and len(pods["items"]) <= 256
    owned = []
    for pod in pods["items"]:
        labels = pod["metadata"].get("labels", {})
        if not all(labels.get(k) == v for k, v in selector.items()):
            continue
        owners = pod["metadata"].get("ownerReferences", [])
        assert len(owners) == 1 and owners[0].get("controller") and owners[0]["kind"] == "ReplicaSet" and owners[0]["apiVersion"] == "apps/v1"
        owner = owners[0]
        rs = request("GET", "/apis/apps/v1/namespaces/" + namespace + "/replicasets/" + owner["name"])
        assert rs["metadata"]["uid"] == owner["uid"] and not rs["metadata"].get("deletionTimestamp")
        parents = rs["metadata"].get("ownerReferences", [])
        assert len(parents) == 1 and parents[0].get("controller") and parents[0]["kind"] == "Deployment" and parents[0]["apiVersion"] == "apps/v1"
        assert parents[0]["name"] == deployment["metadata"]["name"] and parents[0]["uid"] == deployment["metadata"]["uid"]
        assert pod["metadata"]["namespace"] == namespace and pod["metadata"]["uid"] and pod["metadata"]["resourceVersion"]
        owned.append(pod)
    return owned


def restart_application(request, namespace, deployment_uid, sleep):
    deployment = request("GET", "/apis/apps/v1/namespaces/" + namespace + "/deployments/document-qa")
    assert deployment["metadata"]["uid"] == deployment_uid and not deployment["metadata"].get("deletionTimestamp")
    original = controlled_pods(request, namespace, deployment)
    assert len(original) == 1 and not original[0]["metadata"].get("deletionTimestamp")
    pod = original[0]
    request("DELETE", "/api/v1/namespaces/" + namespace + "/pods/" + pod["metadata"]["name"],
            {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": pod["metadata"]["uid"], "resourceVersion": pod["metadata"]["resourceVersion"]}})
    for _ in range(60):
        current = request("GET", "/apis/apps/v1/namespaces/" + namespace + "/deployments/document-qa")
        assert current["metadata"]["uid"] == deployment_uid and current["spec"] == deployment["spec"] and not current["metadata"].get("deletionTimestamp")
        pods = controlled_pods(request, namespace, current)
        if len(pods) == 1 and pods[0]["metadata"]["uid"] != pod["metadata"]["uid"] and not pods[0]["metadata"].get("deletionTimestamp") and any(c["type"] == "Ready" and c["status"] == "True" for c in pods[0].get("status", {}).get("conditions", [])):
            return {"restarted": True, "originalPodUID": pod["metadata"]["uid"], "replacementPodUID": pods[0]["metadata"]["uid"]}
        sleep(1)
    raise RuntimeError("original Pod was not replaced by a ready controlled Pod")


def restart_command():
    script = inspect.getsource(controlled_pods) + "\n" + inspect.getsource(restart_application)
    script += '''
import json, os, ssl, time, urllib.request
context = ssl.create_default_context(cadata=os.environ['RESTART_CA'])
'''
    script += inspect.getsource(NoRedirect)
    script += '''
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
def request(method, path, body=None):
    req = urllib.request.Request('https://kubernetes.default.svc' + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Authorization': 'Bearer ' + os.environ['RESTART_TOKEN'], 'Content-Type': 'application/json'}, method=method)
    with opener.open(req, timeout=10) as response:
        data=response.read((1 << 20) + 1)
    assert len(data) <= 1 << 20
    return json.loads(data)
print(json.dumps(restart_application(request, os.environ['RESTART_NAMESPACE'], os.environ['RESTART_DEPLOYMENT_UID'], time.sleep)))
'''
    return ["python", "-c", script]


def restart_job(operation):
    op = copy.deepcopy(operation)
    op.update(type="job", image="application", command=restart_command(), idempotent=False,
              secretRefs=["restart-ca", "restart-token", "restart-namespace", "restart-deployment-uid"],
              script=dict(inputs=["Current namespace and original Deployment UID selected by the lab operator; explicit API CA and short-lived namespace-scoped token."],
                  permissions=["Get the selected Deployment and its ReplicaSets; list/get/delete Pods in the isolated fixture namespace. No Deployment, Git, Helm or Argo writes."],
                  sideEffects=["Delete one exact original application Pod with UID/resourceVersion preconditions and wait for its ready controlled replacement."],
                  successChecks=["persistence"], retry="manual",
                  resources=dict(cpuMillis=100, memoryBytes=128 << 20, ephemeralStorageBytes=32 << 20, temporaryBytes=16 << 20, gpuCount=0)))
    op.pop("service", None)
    return op


def release_declaration(reference, number, base, platform, fixture):
    release = reference.release_declaration(number, platform, fixture)
    original = copy.deepcopy(release)
    spec = release["spec"]
    spec["deployment"].update(type="gitops", allowedKinds=["Deployment", "Service"],
        gitOps=dict(owner="argocd", revision=base, path="application.yaml",
                    data=dict(pvc="document-qa-data", **({"quiesce": "quiesce", "backup": "backup", "resume": "writes"} if number > 1 else {}))))
    ops = spec["operations"]
    model = next((op for op in ops if op["id"] == "models"), None)
    if model is None:
        model = dict(id="models", type="seed", asset="model", mountPath="/models", storageBytes=128 << 20, idempotent=True, timeoutSeconds=120)
        ops.insert(2, model)
    model.update(pvc=f"document-qa-gitops-model-v{number}", dependsOn=["images"])
    for index, op in enumerate(ops):
        if op["id"] == "acceptance-fixtures":
            op["dependsOn"] = ["deploy"]
        elif op["id"] == "quiesce":
            op["dependsOn"] = ["models"]
        elif op["id"] == "deploy":
            ops[index] = dict(id=op["id"], type="gitops", idempotent=True,
                              dependsOn=["models"] if number == 1 else op["dependsOn"])
        elif op["type"] == "restart":
            ops[index] = restart_job(op)
            ops[index]["dependsOn"].append("acceptance-fixtures")
    transition = spec["transitions"][0]
    transition.update(operations=[op["id"] for op in ops], toDataRevision="schema-v1" if number == 1 else "schema-v2")
    recovery = spec["recovery"][0]
    recovery["gitOpsData"] = dict(pvc="document-qa-data", quiesce="recovery-quiesce", resume="recovery-writes")
    if number == 3:
        recovery["operations"] = [restart_job(op) if op["type"] == "restart" else op for op in recovery["operations"]]
    else:
        seed, restart = recovery["operations"]
        quiesce = reference.job("recovery-quiesce", "job", ["quiesce"], seed["id"])
        inspect_data = copy.deepcopy(quiesce)
        inspect_data.update(id="repair-data-check", dependsOn=[quiesce["id"]],
            command=["python", "-c", "import sqlite3; c=sqlite3.connect('file:/data/app.sqlite?mode=ro', uri=True); assert c.execute('PRAGMA integrity_check').fetchone() == ('ok',)"])
        inspect_data["script"].update(permissions=["Read the existing synthetic database; no Kubernetes API token."], sideEffects=["Verify SQLite integrity without changing or restoring fixture data."])
        writes = reference.job("recovery-writes", "job", ["resume-writes"], inspect_data["id"])
        restart = restart_job(restart)
        restart["dependsOn"] = [writes["id"]]
        recovery.update(dataRevision="schema-v1" if number == 1 else "schema-v2", operations=[seed, quiesce, inspect_data, writes, restart])
    return release, original
