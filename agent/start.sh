#!/usr/bin/env bash
# Registers a self-hosted Azure Pipelines agent, runs jobs, and removes itself.
#
# Ephemeral by design: the container is built and destroyed with the drill, so
# the agent must unregister on the way out. An agent left registered but gone
# shows as offline in the pool, and a pipeline queued against a pool of offline
# agents WAITS rather than failing -- which the drill would read as a run that
# stalled at a checkpoint, and report as an approval holding the line.
set -euo pipefail

: "${AZP_URL:?AZP_URL is required, for example https://dev.azure.com/zuqdah-labs}"
: "${AZP_POOL:?AZP_POOL is required}"
: "${AZP_TOKEN:?AZP_TOKEN is required}"

AZP_AGENT_NAME="${AZP_AGENT_NAME:-guard-drill-$(hostname)-${RANDOM}}"

cleanup() {
  if [ -e ./config.sh ]; then
    echo "Removing the agent registration for ${AZP_AGENT_NAME}..."
    # Retried, because removal races with a job finishing. A failure here
    # leaves a phantom agent, and the next run's pipelines queue against it
    # and look stalled instead of failing.
    for attempt in 1 2 3; do
      if ./config.sh remove --unattended --auth PAT --token "${AZP_TOKEN}" >/dev/null 2>&1; then
        echo "Agent removed."
        return
      fi
      echo "Removal attempt ${attempt} failed."
      sleep 5
    done
    echo "WARNING: the agent could not be unregistered. Remove ${AZP_AGENT_NAME} from the ${AZP_POOL} pool by hand, or the next run's pipelines will queue against an offline agent and look stalled." >&2
  fi
}
trap cleanup EXIT

echo "Resolving the current agent package for ${AZP_URL}..."
# Asking the service which package it wants, rather than pinning a version the
# organization will eventually refuse as too old.
PACKAGE_URL=$(curl -fsSL -u "user:${AZP_TOKEN}" \
  "${AZP_URL}/_apis/distributedtask/packages/agent?platform=linux-x64&top=1" \
  | jq -r '.value[0].downloadUrl')

if [ -z "${PACKAGE_URL}" ] || [ "${PACKAGE_URL}" = "null" ]; then
  echo "Could not resolve an agent package. The most likely cause is a token without Agent Pools (read, manage) scope." >&2
  exit 1
fi

echo "Downloading the agent..."
curl -fsSL "${PACKAGE_URL}" | tar -xz

# The token is passed as an argument, which is how Microsoft's own agent
# container documents it. Inside this container that is acceptable: it is the
# only process, the container is destroyed with the run, and the token is
# scoped to Agent Pools (read, manage) and nothing else. It is still the one
# secret in this lab, and the README says so rather than claiming otherwise.
echo "Configuring ${AZP_AGENT_NAME} in pool ${AZP_POOL}..."
# --unattended so nothing waits on a prompt in a container with no terminal,
# and --replace so a re-run reclaims a name a previous crash left registered.
./config.sh \
  --unattended \
  --agent "${AZP_AGENT_NAME}" \
  --url "${AZP_URL}" \
  --auth PAT \
  --token "${AZP_TOKEN}" \
  --pool "${AZP_POOL}" \
  --work /azp/_work \
  --replace \
  --acceptTeeEula

echo "Agent configured. Waiting for jobs."
# exec so the agent is PID 1 and receives the stop signal directly. Without it
# a docker stop kills this wrapper, the trap never runs, and the registration
# is left behind.
exec ./run.sh "$@"
