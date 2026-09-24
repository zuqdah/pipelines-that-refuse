output "pass" {
  description = "Which policy configuration is currently applied. The drill grades against this, so a mismatch between it and the expectation column is the first thing to check when results look wrong."
  value       = var.pass
}

output "organization_url" {
  value = "https://dev.azure.com/${var.organization}"
}

output "project_name" {
  value = azuredevops_project.drill.name
}

output "project_id" {
  value = azuredevops_project.drill.id
}

output "repository_id" {
  value = azuredevops_git_repository.drill.id
}

output "repository_web_url" {
  value = azuredevops_git_repository.drill.web_url
}

output "default_branch" {
  value = azuredevops_git_repository.drill.default_branch
}

output "environment_name" {
  value = azuredevops_environment.prod.name
}

output "environment_id" {
  value = azuredevops_environment.prod.id
}

output "build_definition_ids" {
  description = "Pipeline ids the drill queues by number rather than by name, because two definitions can share a name across folders."
  value = {
    gated_deploy = azuredevops_build_definition.gated_deploy.id
    secrets      = azuredevops_build_definition.secrets.id
  }
}

# Client ids, not secrets. Each identity is federated, so there is nothing here
# that grants access on its own -- a token still has to be minted by a GitHub
# Actions job whose subject claim matches the federated credential.
output "identity_client_ids" {
  description = "Which client id the drill authenticates as for each identity. The guard matrix names the identity; this maps it to a credential."
  value = {
    for name, app in azuread_application.drill : name => app.client_id
  }
}

output "tenant_id" {
  value = data.azuread_client_config.current.tenant_id
}

# Surfaced deliberately rather than left to be discovered. The point of the
# exemption guard is that this group's membership is the only thing standing
# between a protected branch and a direct push, so a report that did not name
# it would be describing a control it had just proven does not hold.
output "policy_exempt_group" {
  description = "The group holding PolicyExempt and PullRequestBypassPolicy. Branch policies do not apply to its members."
  value = {
    name       = azuredevops_group.exempt.display_name
    descriptor = azuredevops_group.exempt.descriptor
  }
}

output "policy_settings_applied" {
  description = "The four settings that differ between passes, as actually applied. The drill writes these into its report so a result can be read years later without the state file."
  value = {
    reviewer_count                         = local.policy.reviewer_count
    submitter_can_vote                     = local.policy.submitter_can_vote
    on_push_reset_approved_votes           = local.policy.on_push_reset_approved_votes
    allow_completion_with_rejects_or_waits = local.policy.allow_completion_with_rejects_or_waits
    last_pusher_cannot_approve             = local.policy.last_pusher_cannot_approve
  }
}

output "agent_pool_name" {
  value = var.agent_pool_name
}
