#!/usr/bin/env bash
set +x

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# shellcheck disable=SC1091
. "${SCRIPTDIR}"/lib/vars.sh

set -x

sudo virsh net-destroy provisioning || true
sudo virsh net-destroy external || true

sudo pkill -9 -f '/var/lib/libvirt/dnsmasq/external.conf' || true
sudo pkill -9 -f '/var/lib/libvirt/dnsmasq/provisioning.conf' || true

sudo ip link delete external || true
sudo ip link delete ironic-peer || true
sudo ip link delete ironicendpoint || true
sudo ip link delete provisioning || true

sudo virsh net-undefine provisioning || true
sudo virsh net-undefine external || true

minikube delete

# Clean up Docker containers safely
docker ps -a -q | xargs -r docker stop
docker ps -a -q | xargs -r docker rm

sudo rm -rf /opt/metal3-dev-env/ironic/*
sudo rm -rf  /home/metal3ci/go/src/github.com/metal3-io/*

sudo rm -rf "${HOME}"/.minikube
sudo rm -rf "${CAPI_CONFIG_DIR}"
