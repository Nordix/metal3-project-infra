#!/usr/bin/env bash

set -xeu

# Description:
#   Runs the rook tests in the BML


git clone https://github.com/Nordix/rook-ceph-ci.git
cd rook-ceph-ci/examples
git checkout ubuntu

ansible-playbook -i inventory.py deploy-rook.yaml
echo "Rook and ceph successfully deployed"
echo "Running rook ceph tests"

ansible-playbook -i inventory.py ceph-tests.yaml

echo "Rook ceph tests successfully passed"

echo "Tearing down rook ceph cluster"

ansible-playbook -i inventory.py teardown-rook-ceph.yaml
