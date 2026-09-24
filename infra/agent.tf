# The agent pool the drill pipelines run on, and the authorizations without
# which they would never start.
#
# A new Azure DevOps organization gets no Microsoft-hosted parallelism until a
# request is granted, which takes days and sometimes stalls with no reply. A
# self-hosted agent needs no approval and works immediately, so the lab
# registers one in a container and destroys it with everything else. Switching
# to Microsoft-hosted later is a variable change, not a rewrite.

resource "azuredevops_agent_pool" "drill" {
  name = var.agent_pool_name

  # False on purpose. Auto-provisioning creates a queue in every project in the
  # organization, which for a pool that exists for one throwaway project is
  # reach nobody asked for.
  auto_provision = false

  # The agent is a container rebuilt on every run, so there is nothing to keep
  # updated and an auto-update pass only delays the first job.
  auto_update = false

  pool_type = "automation"
}

resource "azuredevops_agent_queue" "drill" {
  project_id    = azuredevops_project.drill.id
  agent_pool_id = azuredevops_agent_pool.drill.id
}

# THE detail that would otherwise cost a live run and produce a false result.
#
# The first time a pipeline uses a queue or an environment, Azure DevOps holds
# the run and asks a human to authorize the resource. That wait is a checkpoint
# on the timeline -- which is exactly what the drill reads to decide whether a
# deployment was blocked pending approval.
#
# So an unauthorized queue does not fail the run. It stalls it in a state that
# looks like the approval check doing its job, and the deploy guard would
# report Blocked having never reached the approval at all: a pass, for the
# wrong reason, indistinguishable from the real thing in the report.
#
# pipeline_id is left unset so every pipeline in the project is authorized. The
# project holds three pipelines, all created by this configuration, all
# destroyed with it.
resource "azuredevops_pipeline_authorization" "queue" {
  project_id  = azuredevops_project.drill.id
  resource_id = azuredevops_agent_queue.drill.id
  type        = "queue"
}

resource "azuredevops_pipeline_authorization" "environment" {
  project_id  = azuredevops_project.drill.id
  resource_id = azuredevops_environment.prod.id
  type        = "environment"
}

resource "azuredevops_pipeline_authorization" "repository" {
  project_id  = azuredevops_project.drill.id
  resource_id = azuredevops_git_repository.drill.id
  type        = "repository"
}
