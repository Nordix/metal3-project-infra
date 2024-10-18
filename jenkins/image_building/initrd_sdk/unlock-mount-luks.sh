#!/bin/bash

# This script is intended to be used in a initrd/initramfs built by
# dracut. The purpose of the script is to unlock and mount the root partition
# and unlock the cloud-init config drive.
#
# The script works also without encryption but it doesn't support the
# scenario when only the config drive is encrypted.
#
# The script has 1 mandatory and 3 optional positional arguments
# Such as:
# - path to the device file of the root partition (mandatory)
# - path to the script that provides the encryption key in plain text format
# - the partition number of the config-drive
# - flag to run in dry run mode (nothig will get created/unlocked/mounted

set -eu

_is_luks() {
    # check blkid record of a device and determine if it is luks encrypted
    # arguments - any path to device file e.g. /dev/sd*,
    # /dev/disk/by-label/<your_label>,by-uuid/<your_id> etc..
    local _record _half_type _full_type _device_path
    _device_path="$1"
    _record="$(blkid "${_device_path}")"
    _half_type="${_record##*TYPE=\"}"
    _full_type="${_half_type%%\"*}"
    if [[ "crypto_LUKS" == "${_full_type}" ]]; then
        return 0
    fi
    return 1
}

_get_partition_from_blkid() {
    # remove all but the device name of the blkid record
    # arguments - any path to deevice file e.g. /dev/sd*,
    # /dev/disk/by-label/<yourlabel>,by-uuid/<your_id> etc..
    local _record _partition_device_path _partition _uuid _blkid
    _partition_device_path="$1"
    _record="$(blkid "${_partition_device_path}")"
    # take the UUID then, run regular blkid w/o arguments and match the UUID
    #_record="${_record##*PARTUUID=}"
    #_uuid="${_record%% *}"
    _uuid="${_record##*PARTUUID=}"

    blkid | while read -r _pname _ _ _iter_uuid; do
       if [[ "${_uuid}" == "${_iter_uuid##*PARTUUID=}" ]]; then
            _partition="${_pname%%\:*}"
            printf "%s" "${_partition##*/}"
            break
       fi
    done
}

_get_part_prefix_for_device() {
    # some block device type will have "p" or "part" partition number
    # prefix associated with it, this function return's the partition prefix
    # arguments - name of a partition that can be found in /proc/partitions
    #             and belongs to the device/disk under analysis
    local _partition
    _partition="$1"
    if [[ "${_partition}" =~ nvme|loop|mmcblk ]]; then
        if [[ "${_partition}" =~ .*part.* ]]; then
            printf "part"
        else
            printf "p"
        fi
    fi
}

_count_parts_for_disk() {
    # Match how many partitions belong to a given disk based on
    # data available in /proc/partitions
    # arguments - name of the disk under /dev (not path just name)
    local _count _disk
    _disk="$1"
    # both the disk and the partitions are listed in the /proc/partitions so
    # there will be an extra record that has to be accounted for
    _count=-1
    # read command will also cut up the columns
    while read -r _ _ _ _part; do
        # if the major device number matches then we have match
        if [[ "${_part}" =~ ${_disk} ]]; then
            _count=$((_count + 1))
        fi
    done < "/proc/partitions"
    printf "%s" "${_count}"
}

_dry_run() {
    # if dry_run mode is enabled commands are just printed not executed
    # Arguments:
    # - anything
    if [[ "${dry_run}" == "false" ]]; then
        "$@"
    else
        printf "DRY_RUN: "
        printf "%s " "${@}"
        printf "\n"
    fi
}

_wait_sec() {
    # Introduce a 1-second delay using the read command
    # sleep might not be available but this way we stress
    # the CPU less
    # Arguments:
    # - number of seconds to wait
    read -r -t "$1" < /dev/zero || true
}

_is_module_builtin() {
    # Check if a kernel module is "built-in" or modular
    # Arguments:
    # - the name of the module to be tested
    local _module
    _module="$1"
    while read -r _attribute _value; do
        if [[ "${_attribute}" == "filename:" ]]; then
            if [[ "${_value}" == "(builtin)" ]]; then
                return 0
            fi
            return 1
        fi
    done < <(modinfo "${_module}")
    return 1
}

_preparation() {
    # Checks if the TPM2.0 and LUKS related tooling and drivers are available.
    # Exits with fault code 1 if the checks fail or the the timeout is reached.
    # Arguments
    # - maximum number of retries
    local _cnt _limit _ready
    # all of the above lister vars are used as numeric values
    declare -i _cnt _limit _ready
    _retry_limit="${1:?}"
    _cnt=0
    _ready=0
    while [[ ${_cnt} -lt ${_retry_limit} ]]; do 
        local _luks_probe _result _tpm_result _crypt_lsmod _dm_lsmod _ready
        # luks_probe, _result are numberic values not boolean
        # _crypt_lsmod, _dm_lsmod are used as booleans
        declare -i _luks_probe _result
        set +e
        # read the persistent "handles" list from the TPM to verify
        # that the tpm2 tool chain is in place and working
        tpm2 getcap handles-persistent
        _tpm_result="$?"
        # Verify that the modules are present and can be loaded
        _luks_probe=0
        modprobe dm_mod 
        _result="$?"
        _luks_probe=$((_luks_probe + _result))
        modprobe dm_crypt
        _result="$?"
        _luks_probe=$((_luks_probe + _result))
        set -e
        if [[ $_luks_probe -gt 0 ]]; then
            # No reason to recheck if the modules can't be loaded they
            # are most likely missing or incompatible
            printf "INFO: dm_mod or dm_crypt modules can't be loaded!\n"
            exit 1
        fi
        # Verify that the modules are loaded successfully
        _crypt_lsmod=1
        _dm_lsmod=1
        while read -r _mod_name _ _ _; do
            if [[ "${_mod_name}" == "dm_crypt" ]]; then
                _crypt_lsmod=0
            elif [[ "${_mod_name}" == "dm_mod" ]]; then
                _dm_lsmod=0
            fi
        done < <(lsmod)
        # If any of the models are seemingly not loaded that might be
        # because lsmod is not displaying builtin modules so it has to
        # be checked if a module is not loaded because it is built in or
        # because it can't load properly
        if [[ ${_dm_lsmod} -eq 1 ]]; then
            _dm_lsmod=$(_is_module_builtin "dm_mod")
        fi
        if [[ ${_crypt_lsmod} -eq 1 ]]; then
            _crypt_lsmod=$(_is_module_builtin "dm_crypt")
        fi
        # Final checks
        _ready=0
        if [[ ${_crypt_lsmod} -eq 0 ]]; then
            printf "INFO: dm_crypt check for LUKS is SUCCESS!\n"
            _ready=$((++_ready))
        else 
            printf "WARNING: dm_crypt for LUKS is FAIL!\n"
        fi 
        if [[ ${_dm_lsmod} -eq 0 ]]; then 
            printf "INFO: dm_mod for LUKS is SUCCESS!\n"
            _ready=$((++_ready))
        else
            printf "WARNING: dm_mod check for LUKS is FAIL!\n"
        fi
        if [[ $_tpm_result -eq 0 ]]; then 
            printf "INFO: tpm2 persistent handes access is SUCCESS!\n"
            _ready=$((++_ready))
        else
            printf "WARNING: tpm2 persistent handes access is FAIL!\n"
        fi
        if [[ ${_ready} -eq 3 ]]; then
            printf "INFO: All checks are OK, proceeding with decryption!\n"
            break
        else
            printf "WARNING: Some checks have FAILED, waiting 1s then retry!\n"
        fi
        _cnt=$((++_cnt))
        _wait_sec 1
    done 
    if [[ ! ${_ready} -eq 3 ]]; then
        printf "ERROR: Some checks have FAILED, TIMEOUT has been reached!\n"
        exit 1
    fi
}

# Start of the execution

config="${1:-/etc/unlock_conf.sh}"

if [[ ! -r "${config}" ]];then
    printf "WARNING: Executing script with default configuration!\n"
else
    printf "INFO: Executing script with configuration from:%s!\n" "${config}"
    # shellcheck disable=SC1090
    source "${config}" 
fi

# Config variables, only configurable via the config file
key_script="${key_script:-/etc/tpm2-unseal-key.sh}"
preparation_timeout="${pre_flight_timeout:-5}"
dry_run="${dry_run:-false}"
root_device_path="${root_device_path:-}"
auth="${auth:-''}"
secret_address="${secret_adress:-''}"
config_drive_part_num="${config_drive_part_num:-}"

# key_command is always evaluetd at the last suitable moment in order
# to retain the file descriptor
key_command="${key_script} ${secret_address} ${auth} ${dry_run}"

printf "INFO: unlock script has been started with the following arguments:\n"
printf "root device path:%s\nconfig-drive partition number:%s\n" \
    "${root_device_path:-auto}" "${config_drive_part_num:-auto}"
printf "key script:%s\nkey commnd:%s\n" "${key_script}" "$key_command"
printf "DRY RUN MODE:%s\n" "${dry_run}"

_preparation "${preparation_timeout}"

# create the mount point for the root file system and evaluate the
# key script
if [[ "${dry_run}" == "false" ]]; then
    mkdir "/realroot"
fi

# different workflows depending on the presence of encryption
# --------------------------------------------------------------------
# nvme, mmc/sd card and loop devices have a partition number prefix
# e.g./dev/nvme0n1 <--> /dev/nvme0n1p1
# --------------------------------------------------------------------
# It is expected that the last partition on the root device is the
# config drive partition thus that is the default logic. In case the user
# specified a value for `config_drive_part_num` the partition count will
# be discarded and the value of `config_drive_part_num` will be used instead.
if _is_luks "${root_device_path}"; then
    printf "Mounting encrypted %s\n" "${root_device_path}"
    _dry_run "/usr/lib/systemd/systemd-cryptsetup" "attach" "realroot" \
            "${root_device_path}" <($key_command) "luks"
    _dry_run "mount" "/dev/mapper/realroot" "/realroot"
    root_partition="$(_get_partition_from_blkid "${root_device_path}")"
    part_prefix="$(_get_part_prefix_for_device "${root_partition}")"
    root_device="${root_partition%"${part_prefix}"*}"
    part_count="$(_count_parts_for_disk "${root_device}")"
    config_drive_common="/dev/${root_device}${part_prefix}"
    if [[ -z "${config_drive_part_num}" ]]; then
        config_drive_path="${config_drive_common}${part_count}"
    else
        config_drive_path="${config_drive_common}${config_drive_part_num}"
    fi
    if [[ "/dev/${root_partition}" == "${config_drive_path}" ]]; then
        # The script considers it a success if it can find only an encrypted
        # root partition but no config drive, some users might simply don't
        # need a config drive
        printf "WARNING: config drive was not detected, exiting!\n"
        exit 0
    fi
    if _is_luks "${config_drive_path}"; then
        # Create an empty file to signal to other services that the config
        # drive was also encrypted, other services might want to know
        # if they need to keep an eye out for the config drive
        true > "/tmp/crypt_config"
        printf "Unlocking config drive %s\n" "${config_drive_path}"
        printf "INFO: config-drive:%s disk:%s part_count:%s " \
            "${config_drive_path}" "${root_device}" "${part_count}"
        printf "root_partition:%s prefix:%s\n" "${root_partition}" \
            "${part_prefix}"
        _dry_run "/usr/lib/systemd/systemd-cryptsetup" "attach" "config-2" \
                "${config_drive_path}" <($key_command) "luks"
        # At this stage the config drive does not need to be mounted, after
        # it is unlocked cloud-init can identify and mount the config drive
        # on its own
    fi

else
    printf "Mounting NON encrypted volume!!!\n"
    _dry_run "mount" "${root_device_path}"  "/realroot"
fi
