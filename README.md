# pipelines-that-refuse

Branch policies, pull request review rules and environment approvals in Azure
DevOps — with **every bypass attempted for real** against a live project, and
graded against what was declared before the run.

## The problem

Every organisation has branch protection. Almost none of them have tested it.

The settings page is the problem: it shows a policy as configured and enforced
whether or not it stops anything, and the things it does not stop are not
visible from it. Three separate mechanisms decide whether a change can reach
`main` — branch policies, repository permissions, and pull request completion
rules — and they fail in different ways, in different places, with the same
reassuring green tick next to all of them.

So the claim "we require two approvals to merge" is usually true, and usually
not what the speaker thinks it means.

## What this proves

A project is created with policies as code, four identities sign in, and each
of them attempts exactly what it should be refused. Then the policy is hardened
and every attempt runs again.

The point is not that some bypasses succeed. It is that the **declared**
expectations are met, which is the only way to tell a real result from a run
that failed to authenticate:

| | |
|---|---|
| Guards attempted | 12, across git, the REST API and pipeline runs |
| Hold identically in both passes | 10 |
| Expected to change once hardened | 2 — the remediation boundary |
| Findings configuration cannot close | 2, reported as findings rather than failures |
| Identities | 4, because the interesting guards cannot be driven by one |
| Result | **12/12 as declared, both passes** |

The expectations live in [`guard-matrix.json`](guard-matrix.json), written
before the drill runs. Without it, a drill that reported "refused" for
everything — which is what a broken login looks like — would pass every guard.

## Refusal is not one thing

This is the distinction the whole lab turns on.

A push blocked by a branch policy and a push blocked by a failed login produce
the same non-zero exit code and the same stderr full of the word *rejected*.
Only one of them says anything about the control. So outcomes are classified by
**cause**, authentication is checked first and deliberately, and anything that
cannot be classified is a failure rather than a pass:

| Outcome | Meaning |
|---|---|
| `RefusedByPolicy` | A branch policy or environment check refused it. The control worked. |
| `RefusedByPermission` | An access control entry refused it. Related, but a different subsystem. |
| `AuthFailure` | Refused before any policy was consulted. Proves nothing, and must never count as a pass. |
| `Allowed` | It went through. |
| `Unknown` | Unclassifiable. Always a failure. |

All of that judgement lives in
[`PipelineGuards`](module/PipelineGuards/PipelineGuards.psm1), which makes no
network call and is covered by 48 unit tests, so it can be audited without an
Azure DevOps organization anywhere in reach.

## The guards worth reading

**An approval outlives the code it was given for.**
`on_push_reset_approved_votes` defaults to **false**. A reviewer approves one
diff, the author pushes a different one, and the pull request completes
carrying a vote for code nobody read. The policy page reads identically before
and after. This is the guard that changes between passes, and it is the reason
the lab bothers with a second identity: a submitter cannot approve their own
work, so producing an approval to then invalidate needs somebody else.

**Completion overrides a reviewer who said no.**
`allow_completion_with_rejects_or_waits` is also off unless somebody knows to
turn it on. Someone reads the change, votes to reject, and the merge proceeds
because the approval count was satisfied elsewhere. Testing this needs a fourth
identity — one to approve and one to object — and borrowing the exempt identity
for it would have blurred what that one proves.

**A blocking policy answers before the `ForcePush` entry.** Force push and
branch deletion are governed by an access control entry, not by branch policy —
but on a *protected* branch the policy refuses first, with `TF402455`, and the
entry is never consulted. So a team that denies force-push and then tests it
against a protected branch will see a refusal and conclude their deny works,
having never exercised it. That is why there is a separate guard for a topic
branch: it is the only place the permission is observable.

**The creator of a branch can force-push to it, whatever the repository says.**
This one came out of a failing guard rather than a design decision, and it is
measured, not inferred:

| branch created by | force push by the author |
|---|---|
| the author | **Allowed** |
| another identity | **RefusedByPermission** |

Same `ForcePush` deny, same identity, same repository. The only variable is who
created the branch. Azure DevOps grants a branch's creator rights that override
a repository-wide deny, so **denying force-push across a repository does not
stop anybody rewriting a branch they made themselves** — which is most of the
branches they will ever push to. The first version of this guard had the author
create the branch and was therefore measuring the creator grant while believing
it was measuring the permission.

**The API is the honest surface.** Completion is tested against REST, not the
web UI, because the UI disables the complete button when policies are unmet —
which proves the button is disabled. The API accepts the request and lets the
server decide. And completion is **asynchronous**: HTTP 200 means accepted, not
merged, so the pull request is read back afterwards. Trusting the status code
would report a bypass that never happened.

## The two that configuration cannot close

These are expected to succeed in both passes. They are findings, not failures,
and the report names them rather than quietly passing.

**`PolicyExempt` overrides every branch policy.** "Bypass policies when
pushing" is a permission, so no policy setting closes it — only group
membership does. The lab creates a group with exactly one member to prove it,
and the report states who is in that group, because a report that did not would
be describing a control it had just demonstrated does not hold. Worth knowing:
the permission grants no access on its own. It is permission to *ignore*
policy, not permission to push.

**Secret masking is defeated by any transform.** Masking is a literal string
replacement over log output. Encode the value, reverse it, or print it one
character at a time and it goes straight through, perfectly readable. This is
not a misconfiguration to fix — it is what masking is, and a pipeline treating
it as a control against the code it runs has misunderstood what it bought.

Both are confirmed live: the plain value came back Masked and the base64 form Leaked, in both passes.

The masking guards run as **two separate pipelines** on purpose. One run
printing both the plain value and a transformed one leaks, and a scan of that
log would report the *masking* guard as failed — of a feature working exactly
as documented.

## Secrets, and the one boundary that cannot be closed

The control plane holds nothing. Both Terraform providers use `use_oidc`, so
the four drill identities are federated app registrations with no client
secret, and each one's Azure DevOps token is minted by exchanging the OIDC
token GitHub Actions issues for the job. There is nothing long-lived to rotate
or leak.

**One exception, stated rather than hidden.** Registering a self-hosted agent
needs a token. Entra service principal registration exists but wants a client
secret, and the device-code alternative is interactive — which an agent rebuilt
on every run cannot use. So agent registration uses a personal access token
scoped to **Agent Pools (read, manage)** and nothing else. It never enters
Terraform, the repository, or a pipeline variable; it is passed to the container
at run time and dies with it.

The value the masking guards hunt for is not in that category and is not
treated as though it were. It is a random string generated per run, recoverable
from Terraform state, in a project destroyed the same day, whose entire purpose
is to be found in a log.

## Cost

**Nothing.** This is the second lab in the series that creates no Azure
resources at all — there is no compute, no storage and no database, only an
Azure DevOps project, four Entra app registrations and a container on the
runner.

Two things could cost money and do not:

**Parallelism.** A new Azure DevOps organization gets no Microsoft-hosted
parallelism until a request is granted, which takes days and sometimes stalls
unanswered. Rather than buy it, the lab registers a self-hosted agent in a
container, which is free and immediate. Switching to Microsoft-hosted later is
`agent_pool_name`, not a rewrite.

**Licences.** Azure DevOps includes five free Basic licences per organization.
The four drill identities use four of them, and they are released on teardown.

## Running it

```bash
scripts/bootstrap.sh --org zuqdah-labs
```

That does everything below except step 1 and the agent token: it creates the
orchestrator application and its federated credential, grants and consents the
Graph permission, adds the principal to the organization and to Project
Collection Administrators, and sets the repository variables and environment.
It is re-runnable — everything it creates is looked up first — and it needs
only `az` and `gh`, since both parse JSON themselves.

Where a preview endpoint refuses it, it says exactly what to click rather than
carrying on and letting the first `terraform apply` fail on an authorization
error.

It deliberately does **not** create the agent's personal access token. A token
cannot be minted through the API without a token, and a script asking for one
in order to create another would be theatre.

The manual equivalent, and what each step is for:

**1. An organization.** Create one at
[dev.azure.com](https://dev.azure.com) — an empty one; Terraform creates the
project. Confirm **Organization settings → Microsoft Entra ID** shows a
connected directory. If it says "not connected", the organization is backed by
a Microsoft account rather than Entra, service principal authentication will
not work, and the whole no-secret design collapses back to personal access
tokens.

**2. An orchestrator identity.** One Entra app registration that Terraform runs
as, federated to this repository:

```bash
az ad app create --display-name pipelines-that-refuse-orchestrator
# then add a federated credential with:
#   issuer   https://token.actions.githubusercontent.com
#   audience api://AzureADTokenExchange
#   subject  repo:<owner>@<OWNER_ID>/pipelines-that-refuse@<REPO_ID>:environment:lab
```

**The subject must be the immutable form**, with GitHub's numeric ids — not the
portable `repo:<owner>/<repo>:environment:lab` that most documentation shows.
GitHub presents the immutable form, Entra matches the subject as an exact
string, and the first live run of this lab died on `AADSTS700213` proving it.
The ids come from `gh api repos/<owner>/<repo> -q '.owner.id, .id'`, and both
the bootstrap script and the workflows build the subject from them so the two
sides cannot drift.

It needs enough Entra permission to create applications
(`Application.Administrator`, or `Application.ReadWrite.All` granted to the
app), and **Project Collection Administrator** in the Azure DevOps
organization: Organization settings → Permissions → Project Collection
Administrators → add the service principal.

**3. An agent token.** A personal access token scoped to **Agent Pools (read,
manage)** only. Nothing else. This is the one secret.

**4. Repository configuration.**

| Kind | Name | Value |
|---|---|---|
| Variable | `ADO_ORGANIZATION` | the organization name, e.g. `zuqdah-labs` |
| Secret | `AZURE_CLIENT_ID` | the orchestrator's client id |
| Secret | `AZURE_TENANT_ID` | the tenant id (a secret so it is masked in public logs) |
| Secret | `AZP_TOKEN` | the Agent Pools token |
| Environment | `lab` | must exist — its name is in the OIDC subject claim |

Then run the **Drill** workflow. It applies the permissive configuration,
drills it, applies the hardened one, drills that, and destroys everything —
including on failure. A nightly **Destroy** at 07:00 UTC sweeps anything a
cancelled run abandoned, asking the organization and Entra directly rather than
trusting a state file, because the run that abandoned resources is the run
whose state was lost.

## Bugs the build found in itself

**The analyzer reported nothing having scanned nothing.** PSScriptAnalyzer
1.25.0 threw `Object reference not set to an instance of an object` on its
first path-based invocation and worked on every call after. The load assertion
carried from an earlier lab proves the analyzer *loaded*; it does not prove the
scan *ran*. CI now scans a snippet with two known violations first and fails if
they are not both reported — which asserts the analyzer works and absorbs the
warm-up in the same step.

**A check that would have passed only on Windows.** The obvious canary for that
step is an aliased `ls`, and `PSAvoidUsingCmdletAliases` does not fire for it on
Linux, where `ls` is a real binary rather than an alias. Verified in the
container instead of assumed.

**An invented fact, caught by reading the schema.** The first draft of the
guard matrix asserted that Azure DevOps ships the minimum-reviewers policy with
self-approval enabled. It does not — `submitter_can_vote` defaults to false.
The real finding in the same schema is stronger, and is now the headline guard.

**An entitlement grants nothing inside a project.** Adding a service principal
to the organization does not give it project access, so without Contributors
membership all eleven guards return `AuthFailure` — refused before any policy
was consulted, proving nothing, and from a distance looking like an extremely
well protected repository. The most dangerous bug available here, because it
fails *safe-looking*.

**Unauthorized resources stall rather than fail.** The first time a pipeline
uses a queue or an environment, Azure DevOps holds the run pending manual
resource authorization — and that wait appears on the timeline as a
**checkpoint**, which is exactly what the drill reads to decide whether a
deployment was blocked by an approval. An unauthorized queue does not fail the
run; it stalls it in a state indistinguishable from the approval working.
`azuredevops_pipeline_authorization` exists in the configuration for that
reason alone.

**A phantom agent looks like a working gate.** A pipeline queued against an
offline agent *waits*. So an agent that failed to unregister would make the
deploy guard pass for the wrong reason, run after run. The container removes
its own registration on exit, and the workflow waits for `Waiting for jobs` in
its log rather than assuming registration succeeded.

**A retry loop that retried with nothing.** The agent's cleanup piped the token
through `"$(cat)"` inside a `for` loop. The pipe is consumed on the first
iteration, so every retry would have passed an empty token and left exactly the
phantom agent the loop existed to prevent.

**One api-version is not enough, and the wrong one looks like an auth
problem.** Azure DevOps ships some 7.1 endpoints as GA and others as preview
only. `connectionData` — which the drill calls to learn the identity id it needs
in order to vote — is preview, while `projects`, `builds`, pull requests and
pipeline runs are not. Asking for `7.1` returns a 400 about the version, and the
bootstrap script's own preflight was written to treat any failure there as "the
organization is not Entra-backed". So the first thing the script did was reject
a perfectly good organization and send the reader off to check a setting that
was already correct. Found by calling it against the real organization rather
than by reasoning about it.

**The OIDC subject format, which my own notes had already recorded.** The first
live run failed at `terraform apply` with `AADSTS700213`: GitHub presented
`repo:zuqdah@32742234/pipelines-that-refuse@1385752564:environment:lab` against
a credential registered for the portable `repo:owner/repo:environment:lab`. An
earlier lab in this series had hit exactly this and written it down. I read
those notes before starting, then wrote the portable form anyway and described
the immutable one as an optional alternative in a comment. Both workflows now
compose the subject from `github.repository_owner_id` and
`github.repository_id`, and the variable has a validation rule that refuses the
portable form — because Entra's refusal names the credential rather than the
format, and every guard would have reported `AuthFailure`.

**A check block that always failed, quietly.** The assertion tying the
pipeline's environment name to the Terraform variable used
`regex("environment:\\s*NAME\\s*$")`. Terraform's `regex` anchors `$` to the end
of the **string**, not the end of a line, so it only matched if the environment
was named on the file's last line. It never was. The check therefore failed on
every apply — as a *warning*, which `terraform apply` prints and carries on
past. A check that always fails is as useless as one that always passes and
quieter about it. Now `contains()` over trimmed lines, with no regex.

**The module written to stop a non-event being read as a result contained
exactly that bug, in mirror image.** Run 4 reported four guards as `Allowed` —
a direct push to a protected branch, a force push, a pull request completed
with no approval, a self-approval accepted. Querying the branch showed `main`
held only the seed commits and `README.md` was untouched. **Nothing had been
pushed at all.** `git push` with nothing to send prints "Everything up-to-date"
and exits **zero**, and the classifier read exit zero as success.

So the function that refuses to call a failed login a policy refusal went on to
call a push that never happened a policy letting one through. It now checks for
that string *before* the exit code and returns `Unknown`, because whether the
branch would have refused a real push is untested. Caught by asking Azure
DevOps what was on the branch — not by re-reading the classifier, which looked
correct.

**One unquoted space broke every commit.** `Start-Process -ArgumentList` joins
an array into a single command line **without quoting**, so
`@('commit', '-am', 'Attempt a direct push')` reached git as separate words:
`-m` took `Attempt` as the message and the rest became *paths*. Every commit
failed, which is why every push was a no-op. `Invoke-Git` now uses
`ProcessStartInfo.ArgumentList`, which escapes each element, and reads both
streams asynchronously — reading one to completion first deadlocks when the
other fills its buffer, which a verbose push will do. Reproduced locally
against a real repository before changing anything:

```
Old  exit=128 commits=1 stderr=fatal: paths 'a ...' with -a does not make sense
New  exit=0   commits=2 stderr=
```

**A 403 that was the policy working.** A completion refused because a blocking
policy is unmet, by a caller without bypass, returns **403** — identical by
status code to a caller with no access whatsoever. Two guards were reported as
`AuthFailure` on that basis, of policies doing their job. The drill now reads
the policy evaluations API and treats that as authoritative. Unreadable
evaluations return `Unknown`, not `Met`: "no blocking policy unmet" and "could
not tell" must not collapse into one answer. And only `approved` counts as
satisfied, because treating `queued` as approved would report a bypass whenever
an evaluation was merely slow.

**Terraform died reconciling drift the lab creates on purpose.** The exempt
identity's push to `main` is a guard *passing*, and it rewrites `README.md`. By
the second apply the seeded files have drifted, Terraform wants to write them
back, that write is a push to `main`, and the hardened policy refuses it with
`TF402455`. The seeds now `ignore_changes` on content. Granting the orchestrator
`PolicyExempt` would also have worked — and would have put a policy bypass in
the lab's own control plane to paper over a problem the lab invented.

**A committed `.sh` needs the executable bit set in the index.** `chmod +x` in
the working tree is not enough; the file commits as `100644` and the runner
refuses it with exit 126, after which both the apply and the destroy retried
twice against a script they could never run. Also already in my notes from an
earlier lab.

**A here-string cannot live in a YAML block scalar.** A PowerShell here-string
must close with `'@` at column 0, and column 0 ends a YAML block. `actionlint`
reports it as "could not parse as YAML", which does not point at the cause.

## Status

| | |
|---|---|
| Unit tests | 48, green, no Azure DevOps organization required |
| PSScriptAnalyzer, `terraform validate`, `tflint`, `actionlint`, `shellcheck` | clean |
| Agent image | builds; carries `base64`, `fold`, `rev`, `tr`; runs non-root |
| Live run against a real organization | **12/12 in both passes** |
| Teardown | **verified** against the organization and Entra afterwards |

From the passing run, against a live Azure DevOps organization:

```
                                             permissive        hardened
push-to-protected-branch                RefusedByPolicy   RefusedByPolicy
force-push-to-protected-branch          RefusedByPolicy   RefusedByPolicy
force-push-to-unprotected-branch    RefusedByPermission   RefusedByPermission
delete-protected-branch                 RefusedByPolicy   RefusedByPolicy
policy-exempt-push                              Allowed   Allowed
complete-pr-without-approval            RefusedByPolicy   RefusedByPolicy
self-approve-own-pr                     RefusedByPolicy   RefusedByPolicy
stale-approval-survives-new-commit              Allowed   RefusedByPolicy
complete-over-outstanding-rejection             Allowed   RefusedByPolicy
deploy-without-environment-approval             Blocked   Blocked
secret-masked-in-log                             Masked   Masked
secret-masking-defeated-by-transform             Leaked   Leaked

12/12 as declared; 0 failed; 0 inconclusive.
```

**Two guards change and ten do not.** That is the whole result. Turning on
`on_push_reset_approved_votes` and `allow_completion_with_rejects_or_waits` is
the difference between a review that means something and a review that does
not — and nothing else on the list moves, so the reader could not have inferred
it from a settings page where all twelve controls looked equally green.

The permissive pass reached 12/12 three separate times, so it is reproducible
rather than lucky.

A run costs **nothing** and takes about twelve minutes for both passes, most of
it waiting: 90 seconds for a service principal to reach Azure DevOps from
Entra, three minutes for a federated credential to propagate, and the rest in
six pipeline runs on a self-hosted agent.

**Twelve live runs to get here** — ten failures. The other labs in this series
took five and nine. Every one of those failures is in the section above, and
three of them were things an earlier lab had already written down and I read
before starting anyway.

## What this does not do

**It does not test a real delivery pipeline.** The pipelines here echo markers.
Build validation, status checks and required templates are all real controls
this lab does not touch, and the deployment deploys nothing — the question is
only whether the job executed.

**It does not cover the whole of branch protection.** Comment resolution, work
item linking, merge strategy restriction and path-based policies each have their
own failure modes and none are attempted.

**It does not test GitHub.** The mechanisms have the same shape and different
names, and a lab claiming to cover both would be testing neither properly.

**It cannot close the two findings**, and does not pretend to. The exemption is
governed by group membership and masking is defeated by arithmetic. The useful
output is knowing that, and knowing who holds the exemption.

Repository policies for credential scanning, file size and path length exist in
the provider and would extend this naturally. They are not here because the
guard matrix is already the part worth reading, and eleven guards that each
mean something beat twenty that partly overlap.
