terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azuredevops = {
      source  = "microsoft/azuredevops"
      version = "~> 1.12"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.5"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
    # Only for a deliberate wait between Entra and Azure DevOps. See
    # identities.tf: a service principal is not visible to Azure DevOps the
    # instant Entra returns it.
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
    }
  }
}

# No personal access token anywhere in this lab's control plane.
#
# use_oidc consumes the token GitHub Actions mints for the job, which the
# provider exchanges for an Azure DevOps token. Nothing long-lived is stored,
# nothing is passed between steps, and there is no secret to rotate or leak --
# which matters more than usual here, since this lab's entire subject is what
# happens when delivery controls are trusted without being tested.
#
# The one exception is agent registration, which needs a token scoped to Agent
# Pools. It never enters Terraform, the repository or a pipeline variable; see
# the README for exactly where that boundary sits and why it cannot be closed.
provider "azuredevops" {
  org_service_url = "https://dev.azure.com/${var.organization}"
  use_oidc        = true
}

provider "azuread" {
  use_oidc = true
}
