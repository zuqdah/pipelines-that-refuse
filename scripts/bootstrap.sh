#!/usr/bin/env bash
#
# One-time setup for the guard drill. Creates the orchestrator identity, gives
# it what it needs in Entra and in Azure DevOps, and configures this
# repository. Re-runnable: everything it creates is looked up first.
#
# It deliberately does NOT create the personal access token the agent needs.
# A token cannot be minted through the API without a token, and a script that
# asked for one in order to create another would be theatre.
#
# Needs: az, gh. Not jq -- both tools parse JSON themselves, and this machine
# does not have it.
set -euo pipefail

ORG=""
REPO=""
ENVIRONMENT="lab"
APP_NAME="pipelines-that-refuse-orchestrator"
ADO_RESOURCE="499b84ac-1321-427f-aa17-267ca6975798" # Azure DevOps, same in every tenant
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000" # Microsoft Graph
# Application.ReadWrite.All, as an application role. The orchestrator creates
# and destroys the four drill identities on every run.
GRAPH_APP_ROLE="1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"

usage() {
  cat <<'USAGE'
Usage: scripts/bootstrap.sh --org <azure-devops-org> [--repo <owner/name>] [--environment <name>]

  --org          Azure DevOps organization name, the segment after dev.azure.com/
  --repo         GitHub repository as owner/name. Defaults to this checkout's origin.
  --environment  GitHub environment named in the OIDC subject. Default: lab

Example:
  scripts/bootstrap.sh --org zuqdah-labs
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --org) ORG="${2:-}"; shift 2 ;;
    --repo) REPO="${2:-}"; shift 2 ;;
    --environment) ENVIRONMENT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [ -z "$ORG" ]; then
  echo "--org is required." >&2
  usage
  exit 2
fi

say() { printf '\n== %s\n' "$1"; }
note() { printf '   %s\n' "$1"; }

# ------------------------------------------------------------------ preflight

say "Checking prerequisites"

for tool in az gh; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is not on PATH." >&2
    exit 1
  fi
done

if ! az account show >/dev/null 2>&1; then
  echo "Not signed in to az. Run: az login" >&2
  echo "Note: device-code login fails on this machine with AADSTS70016; plain 'az login' opens a browser." >&2
  exit 1
fi

TENANT_ID=$(az account show --query tenantId -o tsv)
SIGNED_IN=$(az account show --query user.name -o tsv)
note "Signed in as ${SIGNED_IN} in tenant ${TENANT_ID}"

if ! gh auth status >/dev/null 2>&1; then
  echo "Not signed in to gh. Run: gh auth login" >&2
  exit 1
fi

if [ -z "$REPO" ]; then
  REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)
  if [ -z "$REPO" ]; then
    echo "Could not work out the repository. Pass --repo owner/name." >&2
    exit 1
  fi
fi
note "Repository ${REPO}"

# The IMMUTABLE subject form, built from GitHub's numeric ids.
#
# The portable form repo:OWNER/REPO:environment:ENV is what the documentation
# shows and it does not work: GitHub presents
# repo:OWNER@OWNERID/REPO@REPOID:environment:ENV, Entra matches the subject as
# an exact string, and the first live run of this lab died on AADSTS700213
# saying precisely that. The ids also survive the repository or the account
# being renamed, which the portable form does not.
OWNER_ID=$(gh api "repos/${REPO}" -q .owner.id 2>/dev/null || true)
REPO_ID=$(gh api "repos/${REPO}" -q .id 2>/dev/null || true)
REPO_NAME="${REPO#*/}"
REPO_OWNER="${REPO%%/*}"

if [ -z "$OWNER_ID" ] || [ -z "$REPO_ID" ]; then
  echo "Could not read the numeric ids for ${REPO}. The repository must exist before the federated credential can be registered, because the subject is built from its id." >&2
  exit 1
fi

SUBJECT="repo:${REPO_OWNER}@${OWNER_ID}/${REPO_NAME}@${REPO_ID}:environment:${ENVIRONMENT}"
note "OIDC subject ${SUBJECT}"

# The organization has to be Entra-backed or a service principal cannot be
# added to it at all. Checked before anything is created, because the failure
# otherwise arrives five steps later as an unhelpful 401.
say "Checking the Azure DevOps organization is reachable and Entra-backed"
if ! az rest --resource "$ADO_RESOURCE" --method get \
  --url "https://dev.azure.com/${ORG}/_apis/connectionData?api-version=7.1-preview" \
  --query 'authenticatedUser.providerDisplayName' -o tsv >/dev/null 2>&1; then
  cat >&2 <<EOF
Could not read connectionData from https://dev.azure.com/${ORG}.

Either the organization name is wrong, or it is backed by a Microsoft account
rather than Microsoft Entra ID. Check Organization settings -> Microsoft Entra
ID: if it offers "Connect directory to organization", service principal
authentication will not work and this lab's whole no-secret design collapses
back to personal access tokens.
EOF
  exit 1
fi
note "Organization ${ORG} is reachable"

# --------------------------------------------------------- the orchestrator

say "Creating the orchestrator application"

APP_ID=$(az ad app list --filter "displayName eq '${APP_NAME}'" --query '[0].appId' -o tsv 2>/dev/null || true)
if [ -n "$APP_ID" ] && [ "$APP_ID" != "None" ]; then
  note "Reusing existing application ${APP_ID}"
else
  APP_ID=$(az ad app create --display-name "$APP_NAME" \
    --sign-in-audience AzureADMyOrg --query appId -o tsv)
  note "Created application ${APP_ID}"
fi

SP_OBJECT_ID=$(az ad sp list --filter "appId eq '${APP_ID}'" --query '[0].id' -o tsv 2>/dev/null || true)
if [ -n "$SP_OBJECT_ID" ] && [ "$SP_OBJECT_ID" != "None" ]; then
  note "Reusing existing service principal ${SP_OBJECT_ID}"
else
  SP_OBJECT_ID=$(az ad sp create --id "$APP_ID" --query id -o tsv)
  note "Created service principal ${SP_OBJECT_ID}"
fi

say "Adding the federated credential"

EXISTING_SUBJECT=$(az ad app federated-credential list --id "$APP_ID" \
  --query "[?name=='github-actions'].subject | [0]" -o tsv 2>/dev/null || true)

if [ "$EXISTING_SUBJECT" = "$SUBJECT" ]; then
  note "Federated credential already trusts ${SUBJECT}"
elif [ -n "$EXISTING_SUBJECT" ] && [ "$EXISTING_SUBJECT" != "None" ]; then
  # Replaced rather than left alone. A credential trusting a different subject
  # fails token exchange, and that failure is indistinguishable from a
  # credential that does not exist yet.
  note "Credential trusts '${EXISTING_SUBJECT}', replacing it with '${SUBJECT}'"
  az ad app federated-credential delete --id "$APP_ID" --federated-credential-id github-actions
  az ad app federated-credential create --id "$APP_ID" --parameters "{
    \"name\": \"github-actions\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"${SUBJECT}\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" >/dev/null
  note "Replaced"
else
  az ad app federated-credential create --id "$APP_ID" --parameters "{
    \"name\": \"github-actions\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"${SUBJECT}\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" >/dev/null
  note "Created"
fi

say "Granting Application.ReadWrite.All on Microsoft Graph"
note "The orchestrator creates and deletes the four drill identities each run."

az ad app permission add --id "$APP_ID" \
  --api "$GRAPH_APP_ID" \
  --api-permissions "${GRAPH_APP_ROLE}=Role" >/dev/null 2>&1 || true

# Admin consent needs a Global Administrator or Privileged Role Administrator.
# If it fails the script says exactly what to click rather than carrying on and
# letting the first apply fail on an authorization error.
if az ad app permission admin-consent --id "$APP_ID" >/dev/null 2>&1; then
  note "Admin consent granted"
else
  cat >&2 <<EOF

   WARNING: admin consent was refused.

   Grant it by hand, or the first terraform apply fails creating the drill
   identities: Entra admin centre -> App registrations -> ${APP_NAME} ->
   API permissions -> Grant admin consent.

   This needs Global Administrator or Privileged Role Administrator.
EOF
fi

# ----------------------------------------------------- azure devops access

say "Adding the orchestrator to the Azure DevOps organization"

ENTITLED=$(az rest --resource "$ADO_RESOURCE" --method get \
  --url "https://vssps.dev.azure.com/${ORG}/_apis/graph/serviceprincipals?api-version=7.1-preview.1" \
  --query "value[?originId=='${SP_OBJECT_ID}'].descriptor | [0]" -o tsv 2>/dev/null || true)

if [ -n "$ENTITLED" ] && [ "$ENTITLED" != "None" ]; then
  note "Already in the organization as ${ENTITLED}"
else
  az rest --resource "$ADO_RESOURCE" --method post \
    --url "https://vsaex.dev.azure.com/${ORG}/_apis/serviceprincipalentitlements?api-version=7.1-preview.1" \
    --headers "Content-Type=application/json" \
    --body "{
      \"accessLevel\": { \"accountLicenseType\": \"express\" },
      \"servicePrincipal\": {
        \"origin\": \"aad\",
        \"originId\": \"${SP_OBJECT_ID}\",
        \"subjectKind\": \"servicePrincipal\"
      }
    }" >/dev/null
  note "Added with a Basic licence"

  ENTITLED=$(az rest --resource "$ADO_RESOURCE" --method get \
    --url "https://vssps.dev.azure.com/${ORG}/_apis/graph/serviceprincipals?api-version=7.1-preview.1" \
    --query "value[?originId=='${SP_OBJECT_ID}'].descriptor | [0]" -o tsv 2>/dev/null || true)
fi

say "Making the orchestrator a Project Collection Administrator"
note "It creates and deletes projects, so nothing less will do."

PCA_DESCRIPTOR=$(az rest --resource "$ADO_RESOURCE" --method get \
  --url "https://vssps.dev.azure.com/${ORG}/_apis/graph/groups?api-version=7.1-preview.1" \
  --query "value[?displayName=='Project Collection Administrators'].descriptor | [0]" -o tsv 2>/dev/null || true)

MANUAL_PCA=0
if [ -z "$ENTITLED" ] || [ "$ENTITLED" = "None" ]; then
  note "Could not resolve the service principal's descriptor."
  MANUAL_PCA=1
elif [ -z "$PCA_DESCRIPTOR" ] || [ "$PCA_DESCRIPTOR" = "None" ]; then
  note "Could not resolve the Project Collection Administrators group."
  MANUAL_PCA=1
elif az rest --resource "$ADO_RESOURCE" --method put \
  --url "https://vssps.dev.azure.com/${ORG}/_apis/graph/memberships/${ENTITLED}/${PCA_DESCRIPTOR}?api-version=7.1-preview.1" \
  >/dev/null 2>&1; then
  note "Added to Project Collection Administrators"
else
  note "The membership call was refused."
  MANUAL_PCA=1
fi

if [ "$MANUAL_PCA" -eq 1 ]; then
  cat >&2 <<EOF

   These are preview endpoints and they do get refused. Do it by hand:

     https://dev.azure.com/${ORG}/_settings/groups
     -> Project Collection Administrators -> Members -> Add
     -> search for ${APP_NAME}

   Without it, terraform apply fails creating the project.
EOF
fi

# ----------------------------------------------------- github configuration

say "Configuring the repository"

# A newly created repository refuses its first Actions writes with HTTP 403,
# and the message blames repository write access rather than timing -- which
# sends the reader to check a token scope that was already correct.
#
# Measured on a real run: the variable write succeeded at 20:04, secret writes
# failed for the next several minutes, and the identical secret write succeeded
# at 20:17. So the two surfaces settle independently -- secrets need the
# repository's actions/secrets/public-key endpoint to encrypt against, which
# variables do not touch. That is the likely mechanism rather than a confirmed
# one, so the backoff is generous instead of tuned to a theory.
#
# A failure here is reported and collected, NOT fatal. The Entra and Azure
# DevOps work above is the hard part and it is already done; aborting over a
# repository setting that can be typed in ten seconds means re-running
# everything to get back to this line.
GH_FAILED=()

gh_write() {
  local what="$1"
  shift
  local delay
  for delay in 5 10 20 30 60 0; do
    if "$@" >/dev/null 2>&1; then
      note "Set ${what}"
      return 0
    fi
    if [ "$delay" -gt 0 ]; then
      note "Setting ${what} was refused, retrying in ${delay}s"
      sleep "$delay"
    fi
  done

  echo >&2
  echo "   Could not set ${what} after two minutes of retries. The error:" >&2
  # Run once more unsuppressed, so the real reason is visible rather than a
  # summary of six silent failures.
  "$@" >&2 2>&1 || true
  GH_FAILED+=("$what")
  return 0
}

gh_write "variable ADO_ORGANIZATION" gh variable set ADO_ORGANIZATION --repo "$REPO" --body "$ORG"
# Secrets, not variables. Neither is a credential on its own -- a client id
# and a tenant id grant nothing without a token -- but GitHub masks secrets in
# workflow logs and does not mask variables, and this repository is public.
# The tenant id identifies the directory these labs run in, which is not
# something to publish in plain text in a log for the sake of a convention.
gh_write "secret AZURE_CLIENT_ID" gh secret set AZURE_CLIENT_ID --repo "$REPO" --body "$APP_ID"
gh_write "secret AZURE_TENANT_ID" gh secret set AZURE_TENANT_ID --repo "$REPO" --body "$TENANT_ID"
note "Set variable ADO_ORGANIZATION; set secrets AZURE_CLIENT_ID, AZURE_TENANT_ID"

# The environment is not decoration: its name is inside the OIDC subject the
# federated credential trusts. Without it the workflow cannot run, and the
# token exchange would fail even if it could.
if gh api "repos/${REPO}/environments/${ENVIRONMENT}" >/dev/null 2>&1; then
  note "Environment '${ENVIRONMENT}' already exists"
else
  gh_write "environment ${ENVIRONMENT}" gh api --method PUT "repos/${REPO}/environments/${ENVIRONMENT}"
fi

# --------------------------------------------------------------- what is left

AZP_SET=$(gh secret list --repo "$REPO" --json name -q '.[] | select(.name=="AZP_TOKEN") | .name' 2>/dev/null || true)

say "Done"

# Anything the repository refused is named here with the command to finish it,
# rather than leaving the reader to work out which of several steps did not
# happen from a stack of retry messages.
if [ ${#GH_FAILED[@]} -gt 0 ]; then
  echo
  echo "   The Entra and Azure DevOps setup is complete. These repository"
  echo "   settings were refused and need finishing:"
  echo
  for item in "${GH_FAILED[@]}"; do
    case "$item" in
      "variable ADO_ORGANIZATION")
        echo "     gh variable set ADO_ORGANIZATION --repo ${REPO} --body ${ORG}" ;;
      "secret AZURE_CLIENT_ID")
        echo "     gh secret set AZURE_CLIENT_ID --repo ${REPO} --body ${APP_ID}" ;;
      "secret AZURE_TENANT_ID")
        echo "     gh secret set AZURE_TENANT_ID --repo ${REPO} --body ${TENANT_ID}" ;;
      "environment ${ENVIRONMENT}")
        echo "     gh api --method PUT repos/${REPO}/environments/${ENVIRONMENT}" ;;
      *)
        echo "     ${item}" ;;
    esac
  done
  echo
  echo "   Re-running this script is also safe -- it reuses everything it made."
fi

cat <<EOF

  Application     ${APP_NAME}
  Client id       ${APP_ID}
  Tenant id       ${TENANT_ID}
  Subject         ${SUBJECT}
  Organization    https://dev.azure.com/${ORG}

EOF

if [ -n "$AZP_SET" ]; then
  note "AZP_TOKEN is already set. Nothing left to do -- run the Drill workflow."
else
  cat <<EOF
  One thing left, and it has to be you: the agent registration token.

  A personal access token cannot be created through the API without a token,
  so this is the one step a script cannot take honestly.

    1. https://dev.azure.com/${ORG}/_usersSettings/tokens -> New Token
    2. Scopes: Custom defined -> Agent Pools -> Read & manage
       Nothing else. This token registers an agent and does nothing more.
    3. gh secret set AZP_TOKEN --repo ${REPO}

  Then run the Drill workflow.
EOF
fi

# Entra federated credentials take about three minutes to propagate. Said here
# because the failure for a credential that has not propagated is identical to
# the failure for one whose subject will never match.
printf '\n   Give Entra about three minutes before the first run.\n\n'
