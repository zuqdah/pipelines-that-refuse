resource "azuredevops_project" "drill" {
  name        = var.project_name
  description = "Delivery controls under test. Created and destroyed by the pipelines-that-refuse lab; nothing here is real work."
  visibility  = "private"

  version_control    = "Git"
  work_item_template = "Basic"

  features = {
    # Off because the drill never touches them, and a feature nobody uses is a
    # surface nobody checks.
    boards       = "disabled"
    artifacts    = "disabled"
    testplans    = "disabled"
    repositories = "enabled"
    pipelines    = "enabled"
  }
}

resource "azuredevops_git_repository" "drill" {
  project_id     = azuredevops_project.drill.id
  name           = "guarded"
  default_branch = "refs/heads/main"

  initialization {
    init_type = "Clean"
  }
}

# The pipeline definitions have to live in the repository being guarded,
# because a pipeline stored elsewhere would not be subject to the policies
# under test and the environment check would be the only thing proven.
#
# Written before any branch policy exists. A policy on main refuses pushes, and
# the API this resource uses is a push -- so ordering here is not cosmetic: with
# the policies created first, terraform apply fails on its own repository.
resource "azuredevops_git_repository_file" "pipeline" {
  for_each = {
    "azure-pipelines-gated-deploy.yml" = "${path.module}/../pipelines/gated-deploy.yml"
    "azure-pipelines-secrets.yml"      = "${path.module}/../pipelines/secret-handling.yml"
  }

  repository_id       = azuredevops_git_repository.drill.id
  file                = each.key
  content             = file(each.value)
  branch              = "refs/heads/main"
  commit_message      = "Seed ${each.key} before any policy exists"
  overwrite_on_create = true
}

resource "azuredevops_git_repository_file" "readme" {
  repository_id       = azuredevops_git_repository.drill.id
  file                = "README.md"
  branch              = "refs/heads/main"
  commit_message      = "Seed a file for pull requests to modify"
  overwrite_on_create = true
  content             = <<-EOT
    # guarded

    A throwaway repository whose branch policies are the subject of a drill.
    Created and destroyed by github.com/zuqdah/pipelines-that-refuse.

    Pull requests opened here modify the line below, which exists only to give
    a diff something to change.

    drill-token: seed
  EOT
}

resource "azuredevops_build_definition" "gated_deploy" {
  project_id = azuredevops_project.drill.id
  name       = "gated-deploy"

  ci_trigger {
    use_yaml = false
  }

  repository {
    repo_type   = "TfsGit"
    repo_id     = azuredevops_git_repository.drill.id
    branch_name = azuredevops_git_repository.drill.default_branch
    yml_path    = "azure-pipelines-gated-deploy.yml"
  }

  variable {
    name  = "agentPool"
    value = var.agent_pool_name
  }

  depends_on = [azuredevops_git_repository_file.pipeline]
}

resource "azuredevops_build_definition" "secrets" {
  project_id = azuredevops_project.drill.id
  name       = "secret-handling"

  ci_trigger {
    use_yaml = false
  }

  repository {
    repo_type   = "TfsGit"
    repo_id     = azuredevops_git_repository.drill.id
    branch_name = azuredevops_git_repository.drill.default_branch
    yml_path    = "azure-pipelines-secrets.yml"
  }

  variable {
    name  = "agentPool"
    value = var.agent_pool_name
  }

  # The value the masking guards look for. Long and random on purpose: the
  # drill's punctuation-insensitive scan, which is what catches a secret
  # printed one character at a time, would false-positive against ordinary log
  # text if this were short.
  variable {
    name         = "drillSecret"
    secret_value = random_password.drill_secret.result
    is_secret    = true
  }

  depends_on = [azuredevops_git_repository_file.pipeline]
}

resource "random_password" "drill_secret" {
  length  = 32
  special = false
  upper   = false
}
