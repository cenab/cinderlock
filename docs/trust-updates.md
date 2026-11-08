# Customer trust updates

A release signer can authenticate application content. A customer policy
administrator controls which signers and capabilities the target accepts. These
are separate authorities: a vendor bundle cannot enroll its own policy root.
The wire contract and admission implementation live in
[`internal/trustupdate`](../internal/trustupdate/).

## Establish the baseline independently

Before you execute a plan, enroll the exact policy digest and epoch for its
observed target identity through the customer-managed enrollment process.
Planning reports a missing baseline instead of creating one. Ordinary policy
loading requires the exact local floor; a higher epoch needs explicit admission,
and a lower epoch is a rollback.

Initial enrollment is the place to compare the policy administrator's public
key through your trusted channel. Importing an application release does not
perform this step. After losing local policy history, re-establish the floor
from approved records. An empty database cannot establish which disconnected
policy snapshot is newest.

## Review a policy update

A packet binds its target, previous policy digest and epoch, candidate policy,
validity interval, and decision reference. Verification uses a currently admitted,
nonrevoked policy administrator with global application and channel scopes. Keys
inside the candidate cannot authorize the packet. Known release signing material
cannot serve as the policy administrator, including aliases with different
base64 formatting.

The preview exposes the candidate and changed policy fields. Admission requires
the digest of that exact packet and re-verifies current authority before
committing. Policy epochs advance one step, key identifiers cannot silently
change material, and existing release sequence minima cannot decrease.

Routine administrator rotation uses an overlap: first admit the new administrator
while retaining the signer, then let an already admitted administrator remove
the old key in a later update. Removing or revoking the packet's own signing
administrator is refused.

## Respond to a compromised key

Treat compromise as a customer incident, with a trusted way to deliver the
replacement policy. Cinderlock can reject the old authority after admission; it
cannot establish that a replacement key, operator, workstation, or cluster is
trustworthy. A release key and a policy administrator need different responses.

1. Stop starting Cinderlock mutations against the affected target. Retain its
   journal, policy files, update receipts, approved plans, and current run state.
   A pending worker may still be running. Revoking a key does not terminate it;
   inspect and reconcile that original worker before authorizing recovery.
2. Identify the affected authority and content. Independently review bundles,
   installed releases, and backups admitted during the exposure interval. A
   valid old signature or a passing recorded workflow does not establish that
   content produced by the compromised authority is safe.
3. Prepare a replacement policy with a higher epoch, the compromised material
   revoked or removed, independently admitted replacement keys, and retained
   release sequence minima. Check for aliases of the compromised public-key
   material under other IDs. Retain the local accepted-release history.
4. If an unaffected policy administrator is already admitted, sign and review
   the normal next-epoch update with that key. It can revoke a different
   administrator or a release signer. Do not sign recovery with the compromised
   key or use overlap to keep that key active.
5. If no admitted administrator remains trustworthy, deliver the replacement
   policy through the customer's independent admission process. Select it in a
   private Site file, run `trust admit-policy --site FILE` to inspect its target,
   policy digest, epoch, and previous local floor, then admit that exact digest
   with `--approved-digest`. Use the same state directory and explicit target.
   This local customer action does not rely on an old administrator signature;
   record its decision and policy bytes in the customer's incident records.
6. Confirm that the selected policy matches the admitted floor, generate a new
   plan from independently reviewed content and observed target state, and
   authorize it separately. Old plans and authorizations cannot substitute for
   the changed policy. Test required functions and the declared recovery path
   before declaring the incident resolved.

The out-of-band path advances a retained floor; it rejects a lower epoch and a
different digest at the same epoch. It does not reset accepted release history
or automatically assess installations. Never delete the journal to make a
replacement policy appear new. If the journal, operator host, or cluster may be
compromised, preserve evidence and reconstruct a trusted environment through
the customer's incident procedure before using it for further decisions.

Disconnected sites can only evaluate the policy they have received. Local expiry
and replay checks do not prove delivery of a newer revocation, and a local clock
does not provide an independent time authority. There is no automatic incident
containment, threshold-signature recovery, or production recovery qualification.
The [policy CLI tests](../internal/cli/policy_test.go) exercise exact admission
and stale-floor rejection; [update tests](../internal/trustupdate/trustupdate_test.go)
exercise current authority, revocation, overlap, and replay boundaries.

## Keep publication and activation distinct

Admission writes a new policy file and advances the target's local floor. It
doesn't overwrite the active policy file or change the Site configuration.
Point the Site at the admitted file through your reviewed configuration process.
Until then, the old policy cannot authorize further mutations against the newer
floor. Existing application processes continue running.

File publication and the SQLite journal are separate commit domains. A failure
can leave a prepared file whose floor admission is unconfirmed. Keep that file
for inspection; its presence grants no authority. Reconcile the recorded floor
and receipt before continuing. The receipt and floor transition commit together
in SQLite, including the packet identity, signer, decision reference, and local
time source. Their persistence implementation lives in
[`internal/state/policy.go`](../internal/state/policy.go).

Packet validity and obvious backward clock movement are checked against local
time. Size and lifetime bounds belong to the supported wire profile. Neither a
signature nor a local clock proves that the site received the latest revocation.
Remote policy activation is outside this profile.
