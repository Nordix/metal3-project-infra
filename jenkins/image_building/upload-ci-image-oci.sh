#!/usr/bin/env bash

set -eu

OCI_KEY_TMP="/tmp/oci_key.pem"
cp "${OCI_KEY_FILE}" "${OCI_KEY_TMP}"
chmod 600 "${OCI_KEY_TMP}"

set +x

# shellcheck disable=SC1090
. "${ENV_FILE}"

cleanup() {
    rm -f "${OCI_KEY_TMP}"
}
trap cleanup EXIT

export IMAGE_OS="${IMAGE_OS}"

img_name="$1"
common_image_name="metal3ci-${IMAGE_OS}-latest"

install_oci_client() {
  rm -rf venv
  python3 -m venv venv

  # shellcheck source=/dev/null
  . venv/bin/activate
  # Install OCI CLI
  pip install oci-cli==3.76.0
}

# Upload image to object storage
upload_image_to_bucket() {

  oci os object put \
      --namespace-name "${NAMESPACE_OCID}" \
      --bucket-name "${BUCKET_NAME}" \
      --name "${img_name}".qcow2 \
      --file "${img_name}".qcow2
}

# Delete old image
delete_old_image_from_compute() {
  oci compute image delete \
    --image-id "$(oci compute image list \
      --compartment-id "${COMPARTMENT_OCID}" \
      --display-name "${common_image_name}" \
      --query 'data[0].id' \
      --raw-output)" \
    --force
}

# Import image from object storage
import_image_from_bucket() {
  oci compute image import from-object \
      --compartment-id "${COMPARTMENT_OCID}" \
      --display-name "${common_image_name}" \
      --namespace "${NAMESPACE_OCID}"\
      --bucket-name "${BUCKET_NAME}" \
      --name "${img_name}".qcow2 \
      --operating-system "Linux" \
      --source-image-type QCOW2 \
      --launch-mode PARAVIRTUALIZED

  # Get image id
  IMAGE_ID="$(
  oci compute image list \
    --compartment-id "${COMPARTMENT_OCID}" \
    --display-name "${common_image_name}" \
    --sort-by TIMECREATED \
    --sort-order DESC \
    --query 'data[0].id' \
    --raw-output
  )"

  while true; do
    STATE="$(
      oci compute image get \
        --image-id "$IMAGE_ID" \
        --query 'data."lifecycle-state"' \
        --raw-output
    )"

    echo "Image state: ${STATE}"

    case "$STATE" in
      AVAILABLE)
        break
        ;;
      IMPORTING|PROVISIONING)
        sleep 20
        ;;
      *)
        echo "Image ended in unexpected state: ${STATE}"
        exit 1
        ;;
    esac
  done
}

delete_old_objects() {

  mapfile -t < <(

    oci os object list \
      --namespace-name "${NAMESPACE_OCID}" \
      --bucket-name "${BUCKET_NAME}" \
      --prefix "metal3ci-${IMAGE_OS}" \
      --query 'data[].name' \
      --raw-output \
    | sort -r
  )

  RETENTION_NUM=5

  for ((i="${RETENTION_NUM}"; i<${#MAPFILE[@]}; i++)); do
    oci os object delete \
    --namespace-name "${NAMESPACE_OCID}" \
    --bucket-name "${BUCKET_NAME}" \
    --name "${MAPFILE[i]}" \
    --force
    echo "${MAPFILE[i]} has been deleted!"
  done
}

install_oci_client
upload_image_to_bucket
delete_old_image_from_compute || true
import_image_from_bucket
delete_old_objects || true
