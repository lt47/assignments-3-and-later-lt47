#!/bin/bash
# Script to build image for Raspberry Pi 4 with machine vision support
# Based on: https://github.com/cu-ecen-aeld/yocto-assignments-base/wiki/Build-basic-YOCTO-image-for-RaspberryPi
# Author: Laye Tenumah


git submodule init
git submodule sync
git submodule update

source poky/oe-init-build-env

CONFLINE="MACHINE = \"raspberrypi4-64\""

IMAGE="IMAGE_FSTYPES = \"rpi-sdimg\""

MEMORY="GPU_MEM = \"16\""

LICENCE="LICENSE_FLAGS_ACCEPTED = \"commercial\""

KERNEL_V4L2="IMAGE_INSTALL:append = \" v4l-utils\""

KERNEL_MODULES="KERNEL_MODULE_AUTOLOAD += \"uvcvideo videodev\""

PACKAGES_DEV="IMAGE_INSTALL:append = \" gcc g++ make cmake git\""

PACKAGES_VIDEO="IMAGE_INSTALL:append = \" libv4l v4l-utils\""

PACKAGES_UTILS="IMAGE_INSTALL:append = \" coreutils util-linux procps syslog-ng\""

PACKAGES_DEBUG="IMAGE_INSTALL:append = \" strace gdb\""

PACKAGES_PERF="IMAGE_INSTALL:append = \" rt-tests stress-ng htop\""

SERIAL_CONSOLE="ENABLE_UART = \"1\""

SSH_SERVER="IMAGE_FEATURES:append = \" ssh-server-openssh\""

PACKAGE_MGMT="IMAGE_FEATURES:append = \" package-management\""

TOOLS_DEBUG="IMAGE_FEATURES:append = \" tools-debug\""

DEV_TOOLS="IMAGE_FEATURES:append = \" dev-pkgs tools-sdk\""

ROOTFS_SIZE="IMAGE_ROOTFS_EXTRA_SPACE = \"2097152\""

NUM_CORES=$(nproc)
BB_THREADS="BB_NUMBER_THREADS = \"${NUM_CORES}\""
PARALLEL="PARALLEL_MAKE = \"-j ${NUM_CORES}\""

append_to_local_conf() {
    local config_line="$1"
    local description="$2"
    
    cat conf/local.conf | grep -F "${config_line}" > /dev/null
    local info=$?
    
    if [ $info -ne 0 ]; then
        echo "${config_line}" >> conf/local.conf
    fi
}

append_to_local_conf "${CONFLINE}" "MACHINE setting (Raspberry Pi 4)"
append_to_local_conf "${IMAGE}" "Image format (rpi-sdimg)"
append_to_local_conf "${MEMORY}" "GPU memory (16MB)"
append_to_local_conf "${LICENCE}" "Commercial license acceptance"

append_to_local_conf "${KERNEL_MODULES}" "USB camera kernel modules"
append_to_local_conf "${SERIAL_CONSOLE}" "Serial console (UART)"

append_to_local_conf "${KERNEL_V4L2}" "V4L2 utilities"
append_to_local_conf "${PACKAGES_DEV}" "Development tools"
append_to_local_conf "${PACKAGES_VIDEO}" "Video support"
append_to_local_conf "${PACKAGES_UTILS}" "System utilities"
append_to_local_conf "${PACKAGES_DEBUG}" "Debug tools"
append_to_local_conf "${PACKAGES_PERF}" "Performance tools"

append_to_local_conf "${SSH_SERVER}" "SSH server"
append_to_local_conf "${PACKAGE_MGMT}" "Package management"
append_to_local_conf "${TOOLS_DEBUG}" "Debug tools feature"
append_to_local_conf "${DEV_TOOLS}" "Development tools feature"

append_to_local_conf "${ROOTFS_SIZE}" "Root filesystem size"
append_to_local_conf "${BB_THREADS}" "BitBake threads"
append_to_local_conf "${PARALLEL}" "Parallel make jobs"

bitbake-layers show-layers | grep "meta-raspberrypi" > /dev/null
layer_info=$?
if [ $layer_info -ne 0 ]; then
    bitbake-layers add-layer ../meta-raspberrypi
fi

bitbake-layers show-layers | grep "meta-oe" > /dev/null
layer_oe=$?
if [ $layer_oe -ne 0 ]; then
    bitbake-layers add-layer ../meta-openembedded/meta-oe
    bitbake-layers add-layer ../meta-openembedded/meta-python
    bitbake-layers add-layer ../meta-openembedded/meta-networking
fi

bitbake-layers show-layers

set -e

bitbake core-image-base
