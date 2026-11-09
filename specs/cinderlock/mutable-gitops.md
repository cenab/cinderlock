# Mutable GitOps procedures

The data mechanism and public commands have execution and fault tests. The
[qualification record](../../docs/qualification.md) separately names completed
persistent upgrade, required-workflow failure, and same-source restore through
real Argo. Model/stateless results and other sources do not qualify data
contracts automatically.

A signed `GitOps.data` declaration names the mutable PVC and the exact quiesce,
backup and resume operations in the existing signed DAG. `Recovery.gitOpsData`
uses the same role contract for a separately selected recovery recipe. Naming
roles prevents inference from IDs or script prose; scripts still own their
actual database and application semantics. Job completion is not a storage
fence or a verified backup backend.

The transition contains exactly one source-adoption marker. Supported authored
operations must be ancestors or descendants of it. Fresh native application
artifacts retain separate preparation; acceptance fixtures belong to the check
run. Reject missing/crossed dependencies, ambiguous transitions, a second
application-resource writer and undeclared procedures. Upgrades quiesce before
backup, and other pre-adoption mutations follow that backup. Initial installation
uses an explicitly selected external data PVC and initial Site revision, with
no prior application acceptance or pre-adoption upgrade procedures.

## Execution boundaries

1. **Prepare data:** pin the prior accepted run, its Plan/result and reviewed old
   manifest. Observe that old source and original controller/resource identities
   under current policy. Verify the target's different render independently;
   never manufacture a verified bundle for the old manifest. Bind current
   mutable PVC UID, Site data revision and backup reference, then execute the
   exact signed pre-marker procedures.
2. **Await source adoption:** retain the local active gate and unresolved cluster
   journal. Release only the request Lease. Approval expiry and delayed customer
   source adoption do not release the data gate or grant another mutation.
3. **Check adopted source:** pin the exact completed active predecessor and all
   original terminal workers, including completed Jobs and required receiver
   Pods. Independently observe accepted target source and current dependencies.
   Use fresh current policy, credentials and exact-plan approval. Transfer the
   gate through the existing local transaction and complete both cluster journal
   writes under the Lease before any successor worker. Run post-marker procedures,
   dedicated fixtures, model checks and required application workflows. Only
   successful final acceptance advances the release floor.
4. **Recover data:** a failed successor retains the gate. A separately authorized
   same-source signed restore uses fresh terminal-worker proof and the same exact
   handoff, then its own required recovery checks. Preserve the original failure.
   Customer source reversion and cross-source restoration remain separate scope.

Historical completed staging/preparation/acceptance facts do not require their
old approvals, policy or Secret bytes to remain current. They retain exact
bundle, target, namespace, PVC, worker and result identities. New execution must
satisfy current authority and dependency observations. Registry route changes
cannot pretend an old copy exists at a new address. Current policy can deny
new operations; historical evidence never grants current authority.

Retain the original source revision in the predecessor and the same backup
identity across the waiting boundary. The post-adoption Site declares the signed
transition's target data revision. These remain assertions, not a measured schema
or database hash; vendor scripts enforce actual schema preconditions.

The first supported data profile requires healthy controller reconciliation
through quiescence, one external filesystem data claim, and bounded native
controller/Pod consumer inventory. Unrecorded or ambiguous writers block. Known
previous workers must be terminal; a current authorized worker remains bound
to its original UID and recipe. No custom-controller, storage-fencing, future
writer exclusion, physical isolation or production restore guarantee is implied.

## Evidence and qualification boundaries

The public pre/check/recovery paths, source/target render separation, authority
rotation, failed checks, original worker/claim identities, queued writers,
expiry, interrupted handoff, and initial finalization have regression coverage.
Retained model readers share the data-phase consumer proof; unknown completed
Jobs remain blocked. Current target identity is resolved once per inventory,
not once again for every retained Job.

The named live CPU profile preserves its original failed result and separately
verifies restoration without re-ingestion. Source exports retain dependencies,
toolchains, and legal material, with compilation under disabled Go acquisition.
Hosted checks and hardware qualification remain tied to their exact source and
profile. NVIDIA hardware is deferred by the user; no CPU result substitutes for
GPU inference, allocation, production restore, or physical isolation.
