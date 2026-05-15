#!/usr/bin/env bash
# Pull Nessus CentOS 6/7 Base images

# Log into Docker host
docker login --username nessusBuilder --password tenable https://docker-registry.lab.tenablesecurity.com||exit 1

set -e
BASE_TAG="latest"
docker pull docker-registry.lab.tenablesecurity.com/base/nessus-centos6:${BASE_TAG}||true
docker pull docker-registry.lab.tenablesecurity.com/base/nessus-centos7:${BASE_TAG}||true

SOURCE_DIR=${SOURCE_DIR:="nessus_src_release"}
DEST_DIR=${DEST_DIR:="dockerfiles"}

# CentOS 6:
if [ -e $SOURCE_DIR/Nessus-[0-9]*.[0-9]*.[0-9]*-es6.x86_64.rpm ]; then
    cp $SOURCE_DIR/Nessus-[0-9]*.[0-9]*.[0-9]*-es6.x86_64.rpm $DEST_DIR/nessus-centos6/install/Nessus-es6.x86_64.rpm
    echo "Successfully copied CentOS 6 installers.";
else
    echo "CentOS 6 installer unavailable for copy.";
fi

# CentOS 7:
if [ -e $SOURCE_DIR/Nessus-[0-9]*.[0-9]*.[0-9]*-es7.x86_64.rpm ]; then
    cp $SOURCE_DIR/Nessus-[0-9]*.[0-9]*.[0-9]*-es7.x86_64.rpm $DEST_DIR/nessus-centos7/install/Nessus-es7.x86_64.rpm
    echo "Successfully copied CentOS 7 installers.";
else
    echo "CentOS 7 installer unavailable for copy.";
    exit 1;
fi

BUILD=${IMAGE_TAG:="latest"}

# CentOS 6
if [ -e $SOURCE_DIR/Nessus-[0-9]*.[0-9]*.[0-9]*-es6.x86_64.rpm ]; then
    docker build -t docker-registry.cloud.aws.tenablesecurity.com:8888/services/nessus-centos6:${BUILD} $DEST_DIR/nessus-centos6/
    docker push docker-registry.cloud.aws.tenablesecurity.com:8888/services/nessus-centos6:${BUILD}

    echo "Successfully built and pushed Nessus CentOS 6 images.";
else
    echo "CentOS 6 images are up to date or doesn't exist.";
fi

# CentOS 7
if [ -e $SOURCE_DIR/Nessus-[0-9]*.[0-9]*.[0-9]*-es7.x86_64.rpm ]; then
    docker build -t docker-registry.cloud.aws.tenablesecurity.com:8888/services/nessus-centos7:${BUILD} $DEST_DIR/nessus-centos7/
    docker push docker-registry.cloud.aws.tenablesecurity.com:8888/services/nessus-centos7:${BUILD}

    echo "Successfully built and pushed Nessus CentOS 7 images.";
else
    echo "CentOS 7 images are up to date.";
fi

exit 0
