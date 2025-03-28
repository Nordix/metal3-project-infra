#!/usr/bin/env bash

set -eux

COMMON_IMAGE_NAME="metal3-ci-${IMAGE_OS}-latest"

delete_old_images() {

  # We keep last RETENTION_NUM of metal3ci images and delete old ones when new image has been pushed
  # Example name for metal3ci image: metal3-ci-ubuntu-20240306T0701Z-7b988cb
  RETENTION_NUM=5

  # Delete outdated old images and keep last RETENTION_NUM
  mapfile -t < <(openstack image list -f json | \
    jq .[].Name | \
    sort -r |\
    grep "metal3${IMAGE_TYPE}-${IMAGE_OS}-" | \
    sed 's/"//g')

  for ((i="${RETENTION_NUM}"; i<${#MAPFILE[@]}; i++)); do
    openstack image set "${MAPFILE[i]}" --deactivate
    openstack image delete "${MAPFILE[i]}"
    echo "${MAPFILE[i]} has been deleted!"
  done
}

install_openstack_client() {
  rm -rf venv
  python3 -m venv venv

  # shellcheck source=/dev/null
  . venv/bin/activate
  pip install python-openstackclient==7.0.0
}

upload_ci_image_xerces() {
  img_name="$1"

  # Push image to openstack xerces
  export OS_USERNAME="${OPENSTACK_USERNAME_XERCES}"
  export OS_PASSWORD="${OPENSTACK_PASSWORD_XERCES}"
  export OS_AUTH_URL="https://xerces.ericsson.net:5000"
  export OS_PROJECT_ID="b62dc8622f87407589de9f7dcec13d25"
  export OS_INTERFACE="public"
  export OS_PROJECT_NAME="EST_Metal3_CI"
  export OS_USER_DOMAIN_NAME="xerces"
  export OS_IDENTITY_API_VERSION=3

 # Check if the common image already exists
  if openstack image show "${COMMON_IMAGE_NAME}" &>/dev/null; then
    # Get the original name of the current common image
    original_name=$(openstack image show -f json -c properties "${COMMON_IMAGE_NAME}" | jq -r .properties.image_name)
    # Rename the existing common image back to its original name
    openstack image set --name "${original_name}" "${COMMON_IMAGE_NAME}"
  fi

  qemu-img convert -f qcow2 -O raw "${img_name}".qcow2 "${img_name}".raw

  # Create the new image with the common name
  openstack image create "${COMMON_IMAGE_NAME}" --file "${img_name}".raw --disk-format=raw --property image_name="${img_name}"

  # delete old images (keeps latest five)
  delete_old_images

  #unset openstack variables
  unset "${!OS_@}"
}

# If the script was run directly (i.e. not sourced), run upload functions
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    install_openstack_client
    upload_ci_image_xerces "$@"
fi
