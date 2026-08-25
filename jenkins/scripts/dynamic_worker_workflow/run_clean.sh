#!/usr/bin/env bash

set -eux

# If metal3-dev-env signals root mode, run without sudo.
# Otherwise, default to sudo for backward compatibility.
if [[ "${METAL3_RUN_AS_ROOT:-false}" == "true" ]]; then
    SUDO=""
else
    SUDO="sudo"
fi

IMAGE_OS="${IMAGE_OS:-ubuntu}"

if [[ "${IMAGE_OS}" == "ubuntu" ]]; then
    export CONTAINER_RUNTIME="docker"
    export BOOTSTRAP_CLUSTER="kind"
else
    export BOOTSTRAP_CLUSTER="minikube"
    export CONTAINER_RUNTIME="podman"
fi

if [[ "${REPO_NAME}" == "metal3-dev-env" ]] ||
   [[ "${REPO_NAME}" == "cluster-api-provider-metal3" ]] \
    ; then
    pushd "${HOME}/tested_repo"
else
    pushd "${HOME}/metal3"
fi

make clean

# Clean up test related files and directories
${SUDO} rm -rf /home/metal3ci/tested_repo
${SUDO} rm -rf /home/metal3ci/metal3
${SUDO} rm -rf /opt/metal3-dev-env/*
${SUDO} rm -rf /home/metal3ci/go/src/github.com/metal3-io/*
${SUDO} rm -rf /home/metal3ci/.config/cluster-api/*

# Clean up Docker containers and images
${SUDO} "${CONTAINER_RUNTIME}" container prune --force
${SUDO} "${CONTAINER_RUNTIME}" image prune --force --all
${SUDO} "${CONTAINER_RUNTIME}" volume prune --force
${SUDO} "${CONTAINER_RUNTIME}" system prune --force --all
