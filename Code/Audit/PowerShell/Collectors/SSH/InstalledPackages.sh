#!/bin/bash

# Declare a list of package managers to check
YUM_CMD=$(which yum)
DPKG_CMD=$(which dpkg)
DNF_CMD=$(which dnf)
RPM_CMD=$(which rpm)
ZYPPER_CMD=$(which zypper)
PACMAN_CMD=$(which pacman)
APT_CMD=$(which apt)
SNAP_CMD=$(which snap)
PKG_CMD=$(which pkg)
HP_UX_CMD=$(which swlist)

# Switch on the options
if [[ ! -z $YUM_CMD ]]; then
    yum list installed
elif [[ ! -z $YUM_CMD ]]; then
    dpkg --get-selections | grep -v deinstall
elif [[ ! -z $DNF_CMD ]]; then
    dnf list
elif [[ ! -z $RPM_CMD ]]; then
    rpm -qa
elif [[ ! -z $ZYPPER_CMD ]]; then
    zypper se -s --installed-only
elif [[ ! -z $PACMAN_CMD ]]; then
    pacman -Qe
elif [[ ! -z $APT_CMD ]]; then
    apt list --installed
elif [[ ! -z $SNAP_CMD ]]; then
    snap list
elif [[ ! -z $PKG_CMD ]]; then
    pkg info
elif [[ ! -z $HP_UX_CMD ]]; then
    swlist -v
else
    echo "No known package managers installed"
    exit 1;
fi