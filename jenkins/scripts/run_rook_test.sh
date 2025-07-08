#!/usr/bin/env bash

set -xeu

# Description:
#   Runs the rook tests in the BML


git clone https://github.com/Nordix/rook-ceph-ci.git
cd rook-ceph-ci/examples
ansible-playbook -i inventory.ini deploy-rook.yaml
echo "Rook and ceph successfully deployed"
echo "Running rook ceph tests"

ansible-playbook -i inventory.ini ceph-tests.yaml

echo "Rook ceph tests successfully passed"

echo "Tearing down rook ceph cluster"

ansible-playbook -i inventory.ini teardown-rook-ceph.yaml
