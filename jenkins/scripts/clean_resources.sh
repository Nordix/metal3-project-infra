#!/usr/bin/env bash

set -eu

# Description:
# Runs in main integration cleanup job defined in jjb.
# Consumed by clean_resources.pipeline and cleans any leftover metal3ci
# instances every 8 hours.
# Requires:
#  - OCI CLI credentials sourced from the environment
#    (OCI_CLI_USER, OCI_CLI_TENANCY, OCI_CLI_FINGERPRINT, OCI_CLI_REGION)
#  - OCI_KEY_FILE pointing to the API private key
# Usage:
#  clean_resources.sh
#
CLIENT_VERSION="3.76.0"
COMPARTMENT_OCID="ocid1.tenancy.oc1..aaaaaaaalbjclmsqx5zyjbqgtywhfxns4qavoppuhp6peixiqmm6vu3qyn7a"
OCI_KEY_TMP="/tmp/oci_key.pem"
export OCI_CLI_REGION="eu-paris-1"

cleanup() {
    # Get the current date and time in seconds since the epoch
    current_time=$(date +%s)

    # Define the age threshold (8 hours in seconds)
    age_threshold=$((8 * 60 * 60))

    # List all running instances and loop over them
    oci compute instance list \
        --compartment-id "${COMPARTMENT_OCID}" \
        --lifecycle-state RUNNING \
        --all \
        --query 'data[].{id:id, name:"display-name", created:"time-created"}' \
        --output json | jq -c '.[]?' | while read -r instance; do
        instance_id=$(jq -r '.id' <<< "${instance}")
        instance_name=$(jq -r '.name' <<< "${instance}")
        created_at=$(jq -r '.created' <<< "${instance}")

        # Check if the instance name starts with "jenkins-metal3ci-8c32g-"
        if [[ "${instance_name}" == jenkins-metal3ci-8c32g-* ]]; then
            # Convert instance creation date to seconds since the epoch
            instance_time=$(date --date="${created_at}" +%s)

            # Calculate the age of the instance
            instance_age=$((current_time - instance_time))

            # Check if the instance is older than 6 hours
            if [[ "${instance_age}" -gt "${age_threshold}" ]]; then
                echo -n "Deleting instance: ${instance_id} (Name: ${instance_name}, "
                echo "Created at: ${created_at})"
                # Terminate the instance
                oci compute instance terminate --instance-id "${instance_id}" --force
            fi
        fi
    done
}

# Prepare the API private key for the OCI CLI
cp "${OCI_KEY_FILE}" "${OCI_KEY_TMP}"
chmod 600 "${OCI_KEY_TMP}"
export OCI_CLI_KEY_FILE="${OCI_KEY_TMP}"

remove_key() {
    rm -f "${OCI_KEY_TMP}"
}
trap remove_key EXIT

WORK_VENV="${HOME}/civenv"
WORK_VENV_ACTIVATOR="${WORK_VENV}/bin/activate"

if [[ ! -r "${WORK_VENV_ACTIVATOR}" ]]; then
    sudo apt-get update
    sudo apt-get install -y python3.12-venv
    python3 -m venv "${WORK_VENV}"
fi

# shellcheck source=/dev/null
. "${WORK_VENV_ACTIVATOR}"
# Install OCI client
pip install oci-cli=="${CLIENT_VERSION}"
# export ocicli path
export PATH="${PATH}:${HOME}/.local/bin"

# Cleaning up Oracle Cloud resources
echo "Cleaning up Oracle Cloud"
cleanup

# deactivate the python venv (for non ci use)
deactivate
