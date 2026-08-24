#!/usr/bin/env bash

set -eux

OCI_KEY_TMP="/tmp/oci_key.pem"

set +x

cp "${OCI_KEY_FILE}" "${OCI_KEY_TMP}"
chmod 600 "${OCI_KEY_TMP}"

export OCI_CLI_KEY_FILE="${OCI_KEY_TMP}"
export OCI_CLI_USER="${OCI_CLI_USER}"
export OCI_CLI_TENANCY="${OCI_CLI_TENANCY}"
export OCI_CLI_FINGERPRINT="${OCI_CLI_FINGERPRINT}"

set -x

export OCI_CLI_REGION="eu-paris-1"
export COMPARTMENT_OCID=ocid1.tenancy.oc1..aaaaaaaalbjclmsqx5zyjbqgtywhfxns4qavoppuhp6peixiqmm6vu3qyn7a
export BUCKET_NAME=ImageStorage
export NAMESPACE_OCID=idknxc8t3pjc
export IMAGE_OS="${IMAGE_OS}"

COMMON_IMAGE_NAME="metal3ci-${IMAGE_OS}-latest"
CANDIDATE_IMAGE_NAME="metal3ci-${IMAGE_OS}-staging"

cleanup() {
    rm -f "${OCI_KEY_TMP}"
}
trap cleanup EXIT

action="${1:-}"
img_name="${2:-}"

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

# Delete image by display name if present
delete_image_from_compute_by_name() {
  local image_name="$1"
  local image_id
  image_id="$(oci compute image list \
      --compartment-id "${COMPARTMENT_OCID}" \
      --display-name "${image_name}" \
      --query 'data[0].id' \
      --raw-output)"

  if [ -n "${image_id}" ] && [ "${image_id}" != "" ]; then
    oci compute image delete \
      --image-id "${image_id}" \
      --force
  fi
}

get_image_id_by_name() {
  local image_name="$1"
  oci compute image list \
    --compartment-id "${COMPARTMENT_OCID}" \
    --display-name "${image_name}" \
    --sort-by TIMECREATED \
    --sort-order DESC \
    --query 'data[0].id' \
    --raw-output
}

wait_for_image_available() {
  local image_id="$1"
  local state

  while true; do
    state="$(
      oci compute image get \
        --image-id "${image_id}" \
        --query 'data."lifecycle-state"' \
        --raw-output
    )"

    echo "Image state: ${state}"

    case "${state}" in
      AVAILABLE)
        break
        ;;
      IMPORTING|PROVISIONING)
        sleep 20
        ;;
      *)
        echo "Image ended in unexpected state: ${state}"
        exit 1
        ;;
    esac
  done
}

# Import image from object storage as OCI candidate image
import_candidate_image_from_bucket() {
  oci compute image import from-object \
      --compartment-id "${COMPARTMENT_OCID}" \
      --display-name "${CANDIDATE_IMAGE_NAME}" \
      --namespace "${NAMESPACE_OCID}"\
      --bucket-name "${BUCKET_NAME}" \
      --name "${img_name}".qcow2 \
      --operating-system "Linux" \
      --source-image-type QCOW2 \
      --launch-mode PARAVIRTUALIZED

  local image_id
  image_id="$(get_image_id_by_name "${CANDIDATE_IMAGE_NAME}")"
  wait_for_image_available "${image_id}"
}

promote_candidate_to_latest() {
  local candidate_image_id
  candidate_image_id="$(get_image_id_by_name "${CANDIDATE_IMAGE_NAME}")"

  if [[ -z "${candidate_image_id}" || "${candidate_image_id}" == "null" ]]; then
    echo "Candidate image ${CANDIDATE_IMAGE_NAME} not found"
    exit 1
  fi

  wait_for_image_available "${candidate_image_id}"
  delete_image_from_compute_by_name "${COMMON_IMAGE_NAME}" || true

  oci compute image update \
    --image-id "${candidate_image_id}" \
    --display-name "${COMMON_IMAGE_NAME}" \
    --force
}

delete_old_objects() {

  local objects
  mapfile -t objects < <(
    oci os object list \
      --namespace-name "${NAMESPACE_OCID}" \
      --bucket-name "${BUCKET_NAME}" \
      --prefix "metal3ci-${IMAGE_OS}" \
      --all \
      --query 'data[].name' \
      --raw-output \
    | tr -d '[],"' \
    | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
    | grep -v '^$' \
    | sort -r
  )

  local retention_num=5

  for ((i="${retention_num}"; i<${#objects[@]}; i++)); do
    if oci os object delete \
        --namespace-name "${NAMESPACE_OCID}" \
        --bucket-name "${BUCKET_NAME}" \
        --name "${objects[i]}" \
        --force; then
      echo "Deleted old object: ${objects[i]}"
    else
      echo "WARNING: failed to delete object: ${objects[i]}" >&2
    fi
  done
}

install_oci_client

case "${action}" in
  upload-candidate)
    if [[ -z "${img_name}" ]]; then
      echo "Missing image name. Usage: $0 upload-candidate <image-name>"
      exit 1
    fi
    echo "==> [upload-candidate] START for ${img_name} (os=${IMAGE_OS})"
    upload_image_to_bucket
    echo "==> [upload-candidate] deleting existing candidate image '${CANDIDATE_IMAGE_NAME}' if present"
    delete_image_from_compute_by_name "${CANDIDATE_IMAGE_NAME}" || true
    echo "==> [upload-candidate] importing candidate image '${CANDIDATE_IMAGE_NAME}'"
    import_candidate_image_from_bucket
    echo "==> [upload-candidate] pruning old bucket objects"
    delete_old_objects || true
    echo "==> [upload-candidate] DONE"
    ;;
  promote-candidate)
    promote_candidate_to_latest
    ;;
  *)
    echo "Unknown action: ${action}"
    echo "Usage: $0 <upload-candidate|promote-candidate> [image-name]"
    exit 1
    ;;
esac
