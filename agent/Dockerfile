# A self-hosted Azure Pipelines agent, built and destroyed with the drill.
#
# It exists because a new Azure DevOps organization gets no Microsoft-hosted
# parallelism until a request is granted, which takes days and sometimes stalls
# with no reply. This needs no approval and works immediately.
#
# Nothing in the image is specific to this lab beyond the entrypoint: the
# pipelines it runs only echo markers, so the agent needs a shell, git, and the
# coreutils the masking pipeline uses to transform a value.

FROM ubuntu:24.04

# DEBIAN_FRONTEND so apt never waits on a prompt in a container with no
# terminal, which otherwise hangs the build rather than failing it.
ENV DEBIAN_FRONTEND=noninteractive

# libicu is not optional -- the agent is a .NET application and refuses to
# start without it, with an error about globalization that does not obviously
# mean "install a package".
#
# base64, fold, rev and tr come from coreutils and util-linux, and the masking
# pipeline depends on all four. They are present in this base image, and are
# named here so a future slimmer base does not silently remove the thing two
# guards are measuring.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
        curl \
        git \
        jq \
        libicu74 \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

# The agent refuses to run as root unless told to, and the sanctioned way is
# not to be root. A non-privileged user also means a pipeline step in this lab
# cannot quietly modify the image it runs in.
RUN useradd --create-home --shell /bin/bash agent
WORKDIR /azp
RUN chown agent:agent /azp

COPY --chown=agent:agent start.sh /azp/start.sh
RUN chmod +x /azp/start.sh

USER agent

ENTRYPOINT ["/azp/start.sh"]
