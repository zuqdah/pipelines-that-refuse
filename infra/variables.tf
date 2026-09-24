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
    trust. All three drill identities federate the same subject: they are
    distinguished by which client id the drill authenticates as, not by where
    the token came from.

    The portable form is repo:OWNER/REPO:environment:ENVIRONMENT. The other labs
    in this series use the immutable form, repo:OWNER@OWNERID/REPO@REPOID:...,
    which survives the repository being renamed. Either works; the immutable one
    cannot be written until the repository exists.
  EOT
  type        = string
  default     = "repo:zuqdah/pipelines-that-refuse:environment:lab"
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
