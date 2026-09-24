# The three identities the drill acts as.
#
# Three, not one, because the interesting guards cannot be driven by a single
# identity. A submitter cannot approve their own pull request, so producing an
# approval and then making it stale needs a second identity; and proving that
# PolicyExempt overrides branch policy needs an identity that holds it while
# the others do not. Collapsing them would leave the two most valuable guards
# untestable, which is how a drill ends up only checking the things that are
# easy to check.

locals {
  drill_identities = {
    author = {
      description = "Opens pull requests and pushes. Holds no exemption. Most guards run as this."
      exempt      = false
    }
    reviewer = {
      description = "Approves pull requests, so an approval exists to be made stale."
      exempt      = false
    }
    dissenter = {
      description = "Votes to reject. Exists because 'the approval count is satisfied AND a reviewer objected' needs two voters, and borrowing the exempt identity for it would blur what that one proves."
      exempt      = false
    }
    exempt = {
      description = "Holds PolicyExempt. Exists to prove the exemption overrides policy, and to put a name on who would hold it."
      exempt      = true
    }
  }
}

# A suffix so a re-run after a failed destroy does not collide with application
# names Entra still holds. Entra keeps deleted applications for 30 days and a
# display name is not released while one sits in the bin.
resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
  numeric = true
}

resource "azuread_application" "drill" {
  for_each = local.drill_identities

  display_name     = "guard-drill-${each.key}-${random_string.suffix.result}"
  description      = each.value.description
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azuread_client_config.current.object_id]
}

data "azuread_client_config" "current" {}

resource "azuread_service_principal" "drill" {
  for_each = local.drill_identities

  client_id                    = azuread_application.drill[each.key].client_id
  app_role_assignment_required = false
  owners                       = [data.azuread_client_config.current.object_id]

  description = each.value.description
}

# Federated credentials, so no identity in this lab holds a secret. All three
# trust the same subject: they are told apart by which client id the drill
# authenticates as, not by where the token came from.
resource "azuread_application_federated_identity_credential" "drill" {
  for_each = local.drill_identities

  application_id = azuread_application.drill[each.key].id
  display_name   = "github-actions"
  description    = "GitHub Actions OIDC for the guard drill."
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = var.github_oidc_subject
}

# Each identity has to exist in the organization before it can be given
# permissions or asked to vote. express is the Basic licence; a new
# organization includes five of them free, and this lab uses three.
# A service principal is not visible to Azure DevOps the instant Entra returns
# it. On the second live run, two of the four entitlements failed with:
#
#   VS403283: Could not add user '<id>' at this time
#
# That is a hard error, not a timeout, so the entitlement's own create timeout
# does nothing for it -- Terraform does not retry a 5000. Waiting is crude but
# it is the honest shape of the problem: there is nothing to poll, because the
# principal exists in Entra and simply has not propagated to the other service.
resource "time_sleep" "principals_propagate" {
  depends_on      = [azuread_service_principal.drill]
  create_duration = "90s"
}

resource "azuredevops_service_principal_entitlement" "drill" {
  for_each = local.drill_identities

  origin_id            = azuread_service_principal.drill[each.key].object_id
  account_license_type = "express"

  depends_on = [time_sleep.principals_propagate]

  # Kept alongside the wait rather than instead of it. The wait covers
  # propagation; this covers the entitlement call itself being slow, which is a
  # different thing. Everything downstream references .descriptor, which does
  # not resolve until the graph subject materialises.
  timeouts {
    create = "10m"
  }
}
