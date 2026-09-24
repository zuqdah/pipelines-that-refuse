# The exemption, and the environment gate.
#
# These two are the guards that configuration cannot close and the guard that
# should hold regardless of configuration, so they sit together.

# An entitlement puts an identity in the ORGANIZATION. It grants nothing inside
# a project, so without this every guard would come back AuthFailure -- refused
# before any policy was consulted, proving nothing, and looking from a distance
# like a very well protected repository.
#
# Contributors is the right group for identities under test: it is what a real
# engineer holds. The controls being measured are then layered on top, so a
# refusal is attributable to a policy or to an explicit deny rather than to the
# identity simply having no access.
data "azuredevops_group" "contributors" {
  project_id = azuredevops_project.drill.id
  name       = "Contributors"
}

resource "azuredevops_group_membership" "contributors" {
  group = data.azuredevops_group.contributors.descriptor
  mode  = "add"
  members = [
    for name in keys(local.drill_identities) :
    azuredevops_service_principal_entitlement.drill[name].descriptor
  ]
}

# git_permissions assigns to a GROUP, not to an identity, so proving that
# PolicyExempt overrides branch policy needs a group with exactly one member.
# That is not an inconvenience worth hiding: it is the reason this exposure is
# managed by membership rather than by policy, and the reason the report has to
# name who is in the group instead of claiming the branch is protected.
resource "azuredevops_group" "exempt" {
  scope        = azuredevops_project.drill.id
  display_name = "guard-drill-policy-exempt"
  description  = "Holds PolicyExempt so the drill can prove branch policies are subject to an override. One member, by design."
}

resource "azuredevops_group_membership" "exempt" {
  group = azuredevops_group.exempt.descriptor
  mode  = "add"
  members = [
    azuredevops_service_principal_entitlement.drill["exempt"].descriptor
  ]
}

resource "azuredevops_git_permissions" "exempt" {
  project_id    = azuredevops_project.drill.id
  repository_id = azuredevops_git_repository.drill.id
  principal     = azuredevops_group.exempt.descriptor

  permissions = {
    # "Bypass policies when pushing". Overrides every branch policy on the
    # repository for anyone holding it.
    #
    # On its own it grants no access at all -- the exemption is permission to
    # ignore policy, not permission to push. The identity holding it is a
    # Contributor like the others; this is the single extra grant that is the
    # difference between the guard that fails and the guards that hold.
    PolicyExempt = "Allow"

    # The pull request equivalent, granted alongside so the report can state
    # both halves of the exposure rather than leaving the reader to assume the
    # first implies the second.
    PullRequestBypassPolicy = "Allow"
  }
}

# Force push and branch deletion are governed here rather than by branch
# policy, which is the distinction two of the guards exist to prove. Denying
# them explicitly for the identities under test means a refusal is attributable
# to a rule somebody wrote, not to a default that could change.
resource "azuredevops_group" "restricted" {
  scope        = azuredevops_project.drill.id
  display_name = "guard-drill-restricted"
  description  = "The identities whose delivery controls are being measured."
}

resource "azuredevops_group_membership" "restricted" {
  group = azuredevops_group.restricted.descriptor
  mode  = "add"
  members = [
    azuredevops_service_principal_entitlement.drill["author"].descriptor,
    azuredevops_service_principal_entitlement.drill["reviewer"].descriptor,
  ]
}

resource "azuredevops_git_permissions" "restricted" {
  project_id    = azuredevops_project.drill.id
  repository_id = azuredevops_git_repository.drill.id
  principal     = azuredevops_group.restricted.descriptor

  permissions = {
    # Explicit denies rather than relying on Contributors not granting these.
    # In Azure DevOps a Deny beats an Allow, including an inherited one, so a
    # refusal here is attributable to a rule somebody wrote -- not to a default
    # that a future change to the built-in group could quietly remove.
    #
    # One permission, two guards: ForcePush governs force pushing AND deleting
    # branches ("Force push (rewrite history, delete branches and tags)"), so
    # force-push-to-protected-branch and delete-protected-branch are both
    # expected to be refused by permission and both come from this line. Worth
    # knowing, because hardening the branch policy moves neither of them.
    ForcePush = "Deny"

    # Explicit, so the contrast with the exempt group is a decision rather than
    # an accident of which groups happen to hold what.
    PolicyExempt            = "Deny"
    PullRequestBypassPolicy = "Deny"

    # An identity that can grant itself the exemption is not constrained by it,
    # and every guard measuring the exemption would be measuring nothing.
    ManagePermissions = "Deny"
    EditPolicies      = "Deny"
  }
}

resource "azuredevops_environment" "prod" {
  project_id  = azuredevops_project.drill.id
  name        = var.environment_name
  description = "Carries an approval check. A deployment here must not execute before somebody approves it."
}

# The gate whose job is to stop a deployment rather than to record that one
# happened. requester_can_approve is left at its default of false: an approval
# the requester can grant themselves is a log entry, not a control.
resource "azuredevops_check_approval" "prod" {
  project_id           = azuredevops_project.drill.id
  target_resource_id   = azuredevops_environment.prod.id
  target_resource_type = "environment"

  requester_can_approve      = false
  minimum_required_approvers = 1
  approvers = [
    azuredevops_group.restricted.origin_id
  ]

  instructions = "Do not approve. The drill measures that the deployment did not run; approving it would end the only thing being measured."

  # Twelve hours. The drill reads the deployment state and then destroys the
  # project, so nothing waits this long -- but a check that timed out quickly
  # would let a slow drill mistake an expiry for a refusal.
  timeout = 720
}
