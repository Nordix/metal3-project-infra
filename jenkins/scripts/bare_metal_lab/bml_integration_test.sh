#!/usr/bin/env bash

set -xeu

# Description:
#   Runs the integration tests in the BML
# Usage:
#  bml_integration_test.sh
#

# . bml_test/lib/vars.sh

# # Function to generate BMH manifest from template
# generate_and_apply_bmh() {
#   local name=$1
#   local mac=$2
#   local device=$3
#   local ip=$4

#   export NAME="$name"
#   export MAC_ADDRESS="$mac"
#   export ROOTDEVICEHINT="$device"
#   export IP_ADDRESS="$ip"
#   export USER=$(echo -n "${BML_ILO_ADMIN}" | base64)
#   export PASSWORD=$(echo -n "${BML_ILO_PASSWORD}" | base64)

#   envsubst < "${CI_DIR}/bml_test/lib/templates/bmhosts_crs.yaml" > "${CI_DIR}/${name}.yaml"
# }

CI_DIR="$(dirname "$(readlink -f "${0}")")"

# ./bml_test/02_configure_host.sh

# ./bml_test/03_launch_bootstrap_cluster.sh

# ./bml_test/04_verify.sh

# Generate manifests for each host
# generate_and_apply_bmh "${BMH_NAME_1}" "${MAC_ADDRESS_1}" "${ROOTDEVICEHINT_1}" "${IP_ADDRESS_1}"
# generate_and_apply_bmh "${BMH_NAME_2}" "${MAC_ADDRESS_2}" "${ROOTDEVICEHINT_2}" "${IP_ADDRESS_2}"

# Apply manifests to cluster
#kubectl apply -f "${CI_DIR}"/bml_test/manifests/

CI_DIR="$(dirname "$(readlink -f "${0}")")"

echo "Setting up the lab"
#ANSIBLE_FORCE_COLOR=true ansible-playbook -v "${CI_DIR}"/cleanup-lab.yaml
ANSIBLE_FORCE_COLOR=true ansible-playbook -v "${CI_DIR}"/deploy-lab.yaml

echo "Running the tests"

#make provision
#make pivot

# Run Pods Scaling test
#export ANSIBLE_CONFIG="${CI_DIR}"/tasks/pod_scaling/ansible.cfg
#ANSIBLE_FORCE_COLOR=true ansible-playbook -b "${CI_DIR}"/tasks/pod_scaling/pod-scaling.yaml -i "${CI_DIR}"/tasks/pod_scaling/inventory.ini

#make repivot
#make deprovision
