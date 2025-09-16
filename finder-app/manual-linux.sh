#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

if mkdir -p ${OUTDIR} ; 
then
       echo "Successfully created directory - ${OUTDIR}."
else
       echo "Failed to create directory - ${OUTDIR}."
fi 
   

#cd "$OUTDIR"
pushd ${OUTDIR}
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    pushd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # TODO: Add your kernel build steps here
    # Clean up 
    #make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} mrproper
    make mrproper
    # Configure for virtual arm dev board in QEMU
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig
    # Build kernel image for booting with QEMU
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j$(nproc) all
    popd
fi

echo "Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}/

echo "Creating the staging directory for the root filesystem"
#cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
    echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
mkdir -p ${OUTDIR}/rootfs
pushd ${OUTDIR}/rootfs
mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr var
mkdir -p usr/bin usr/lib usr/sbin
mkdir -p var/log
popd

#cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
    git clone git://busybox.net/busybox.git
    pushd busybox
    git checkout ${BUSYBOX_VERSION}
    popd
    # TODO:  Configure busybox
else
    cd busybox
fi

# TODO: Make and install busybox
pushd "${OUTDIR}/busybox"
make distclean
make defconfig
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX=${OUTDIR}/rootfs ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install
popd


echo "Library dependencies"
${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/busybox | grep "Shared library"

# TODO: Add library dependencies to rootfs
CROSS_SYSROOT="$(${CROSS_COMPILE}gcc -print-sysroot)"
LD_PROGRAM="$(${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/busybox | \
	awk -F: '/program interpreter:/ {print substr($2, 2, length($2)-2)}')"
SHLIB_ARR=($(${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/busybox | \
	awk -F: '/Shared library:/ {print substr($2, 3, length($2)-3)}'))

cp ${CROSS_SYSROOT}${LD_PROGRAM} ${OUTDIR}/rootfs${LD_PROGRAM}
for File in ${SHLIB_ARR[@]}; do
    cp ${CROSS_SYSROOT}/lib64/$File ${OUTDIR}/rootfs/lib64/
done

# TODO: Make device nodes
sudo mknod -m 666 ${OUTDIR}/rootfs/dev/null c 1 3
sudo mknod -m 666 ${OUTDIR}/rootfs/dev/console c 5 1

# TODO: Clean and build the writer utility
pushd ${FINDER_APP_DIR}
make clean
make CROSS_COMPILE=${CROSS_COMPILE}
popd

# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs
FINDER_APP_FILES=(autorun-qemu.sh finder.sh finder-test.sh writer)
for File in ${FINDER_APP_FILES[@]}; do
    cp ${FINDER_APP_DIR}/$File ${OUTDIR}/rootfs/home/
done

# Copy finder-test.sh dependencies 
cp -a ${FINDER_APP_DIR}/../conf ${OUTDIR}/rootfs/
pushd ${OUTDIR}/rootfs/home/
ln -s ../conf .
popd

# TODO: Chown the root directory
sudo chown -R root:root ${OUTDIR}/rootfs

# TODO: Create initramfs.cpio.gz
pushd ${OUTDIR}/rootfs
find . | cpio -H newc -o --owner root:root > ${OUTDIR}/initramfs.cpio
gzip -f ${OUTDIR}/initramfs.cpio
popd
