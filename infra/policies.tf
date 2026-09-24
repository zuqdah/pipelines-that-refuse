# The branch policy, in the two configurations the drill is graded against.
#
# Only the minimum-reviewers policy changes between passes. Everything else
# about the project is identical, so any difference the drill reports is
# attributable to these four settings rather than to the run.

# The deployment job names its environment as a literal, because Azure DevOps
# resolves `environment:` at compile time and a runtime variable there is not
# reliably honoured. That leaves the name written in two places, so it is
# asserted rather than trusted: a typo would send the deployment to an
# environment carrying no check, it would run, and the drill would faithfully
# report that the gate did not hold -- of a gate that was never in the path.
# That is a false negative reported with total confidence, which is the failure
# mode this whole lab is about.
check "pipeline_targets_the_checked_environment" {
  assert {
    condition = can(regex(
      "environment:\\s*${var.environment_name}\\s*$",
      join("\n", [for line in split("\n", file("${path.module}/../pipelines/gated-deploy.yml")) : trimspace(line)])
    ))
    error_message = "pipelines/gated-deploy.yml does not target environment '${var.environment_name}'. The approval check would not be in the deployment's path and the drill would measure nothing."
  }
}

locals {
  hardened = var.pass == "hardened"

  policy = {
    # Held constant. If this rose between passes the comparison would be
    # confounded: "more reviewers" and "votes reset on push" are different
    # controls and only one of them is the point.
    reviewer_count = var.reviewer_count

    # Off in both passes, at the provider's documented default. The drill
    # proves it rather than assuming it, and the reviewer identity only earns
    # its place because this is false.
    submitter_can_vote = false

    # THE finding. False by default, which means an approval outlives the diff
    # it was given for: a reviewer approves, the author pushes something else,
    # and the pull request completes carrying a vote for code nobody read.
    on_push_reset_approved_votes = local.hardened

    # The second one. False by default, so a reviewer who read the change and
    # voted to reject is overridden as long as the approval count is satisfied
    # elsewhere.
    allow_completion_with_rejects_or_waits = !local.hardened

    # Not measured by a guard of its own, but hardened alongside the others
    # because leaving it off while claiming the branch is protected would be
    # dishonest about what "hardened" means here.
    last_pusher_cannot_approve = local.hardened
  }
}

resource "azuredevops_branch_policy_min_reviewers" "drill" {
  project_id = azuredevops_project.drill.id

  enabled  = true
  blocking = true

  settings {
    reviewer_count                         = local.policy.reviewer_count
    submitter_can_vote                     = local.policy.submitter_can_vote
    on_push_reset_approved_votes           = local.policy.on_push_reset_approved_votes
    allow_completion_with_rejects_or_waits = local.policy.allow_completion_with_rejects_or_waits
    last_pusher_cannot_approve             = local.policy.last_pusher_cannot_approve

    scope {
      repository_id  = azuredevops_git_repository.drill.id
      repository_ref = azuredevops_git_repository.drill.default_branch
      match_type     = "Exact"
    }
  }

  # The seeded files are pushed to main by the API, and a blocking policy on
  # main refuses that push. Without this ordering the first apply fails inside
  # its own repository, which reads as a provider bug rather than the policy
  # doing exactly what it was asked to.
  depends_on = [
    azuredevops_git_repository_file.pipeline,
    azuredevops_git_repository_file.readme,
  ]
}
