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
administrator is refused. Compromise recovery still needs independently trusted
customer authority; possession of a compromised key does not prove recovery.

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
Threshold signing, remote activation, and automatic compromise recovery are
outside this profile.
