variable "organization" {
  description = "Azure DevOps organization name, the segment after dev.azure.com/."
  type        = string
  default     = "zuqdah-labs"

  validation {
    # A full URL here produces an org_service_url with the host twice, and the
    # provider's error for that names an authentication problem rather than a
    # malformed URL.
    condition     = !can(regex("^https?://|/", var.organization))
    error_message = "Give the organization name only, not a URL and no slashes."
  }
}

variable "project_name" {
  description = "Project created for the drill. Torn down with everything else."
  type        = string
  default     = "guard-drill"
}

# The whole two-pass design turns on this one variable. "permissive" configures
# the minimum-reviewers policy with only its required setting, leaving every
# optional protection at its documented default of off. "hardened" turns them
# on. The guard matrix declares what each pass should produce before either
# runs, so the difference is a measurement rather than a demonstration.
variable "pass" {
  description = "Which policy configuration to apply: permissive or hardened."
  type        = string
  default     = "permissive"

  validation {
    condition     = contains(["permissive", "hardened"], var.pass)
    error_message = "pass must be permissive or hardened."
  }
}

variable "reviewer_count" {
  description = "Approvals the branch policy requires. Held constant across both passes so the difference between them is never just 'more reviewers'."
  type        = number
  default     = 1

  validation {
    condition     = var.reviewer_count >= 1
    error_message = "A policy requiring zero approvals is not a policy."
  }
}

variable "github_oidc_subject" {
  description = <<-EOT
    The subject claim GitHub Actions presents, which the federated credentials
    trust. All four drill identities federate the same subject: they are
    distinguished by which client id the drill authenticates as, not by where
    the token came from.

    It must be the IMMUTABLE form:

      repo:OWNER@OWNERID/REPO@REPOID:environment:ENVIRONMENT

    not the portable repo:OWNER/REPO:environment:ENVIRONMENT. This is not a
    preference. The first live run failed with AADSTS700213 because GitHub
    presented 'repo:zuqdah@32742234/pipelines-that-refuse@1385752564:environment:lab'
    against a credential registered for the portable form, and Entra matches
    the subject as an exact string.

    The workflow composes it from github.repository_owner_id and
    github.repository_id, so there is nothing to keep in sync by hand. There is
    deliberately no default: a wrong default here produces an authentication
    failure whose message points at the credential rather than at the value,
    and every guard would report AuthFailure -- which looks like a very well
    protected repository.
  EOT
  type        = string

  validation {
    condition     = can(regex("^repo:[^/@]+@[0-9]+/[^/@]+@[0-9]+:", var.github_oidc_subject))
    error_message = "github_oidc_subject must use the immutable form repo:OWNER@OWNERID/REPO@REPOID:... The portable form is silently refused by Entra at token exchange, not here."
  }
}

variable "environment_name" {
  description = "The pipeline environment carrying the approval check."
  type        = string
  default     = "prod-lab"
}

variable "agent_pool_name" {
  description = <<-EOT
    Agent pool the drill pipelines run on. Defaults to the self-hosted pool this
    lab registers in a container, because a new Azure DevOps organization gets
    no Microsoft-hosted parallelism until a request is granted, which takes days
    and sometimes stalls. Set this to "Azure Pipelines" once that grant lands.
  EOT
  type        = string
  default     = "guard-drill-pool"
}
