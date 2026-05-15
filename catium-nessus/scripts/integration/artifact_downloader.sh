#!/usr/bin/env bash

# Copies Nessus source into expected locations for docker build command to succeed.
set -e

SOURCE_DIR=${SOURCE_DIR:="nessus_src_release"}
DEST_DIR=${DEST_DIR:="dockerfiles"}

mkdir -p tmp/
rm -rf tmp/*


# CentOS 5/6/7:
if [ -e $SOURCE_DIR/Nessus-[0-9]*.[0-9]*.[0-9]*-es6.x86_64.rpm ]; then
    cp $SOURCE_DIR/Nessus-[0-9]*.[0-9]*.[0-9]*-es6.x86_64.rpm tmp/
    echo "Successfully copied CentOS 6 installers.";
else
    echo "CentOS 6 installer unavailable for copy.";
fi

if [ -e $SOURCE_DIR/Nessus-[0-9]*.[0-9]*.[0-9]*-es7.x86_64.rpm ]; then
    cp $SOURCE_DIR/Nessus-[0-9]*.[0-9]*.[0-9]*-es7.x86_64.rpm tmp/
    echo "Successfully copied CentOS 7 installer.";
else
    echo "CentOS 7 installer unavailable for copy.";
    exit 1;
fi

rm -rf nessus_src_release/*
mv tmp/* nessus_src_release/
rm -rf tmp/

exit 0

