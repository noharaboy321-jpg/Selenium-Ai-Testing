#!/usr/bin/env bash

snapshot="snapshot"

if [ "${3}" == "master" -o "${3}" == "release" ]
then
    snapshot=""
fi

cat > ~/.pypirc <<EOF
[distutils]
index-servers =
    nexus
[nexus]
repository =  https://nexus.cloud.aws.tenablesecurity.com/repository/tenable_pypihosted${snapshot}/
username = $1
password = $2
EOF

# Setup Python environment
python3 --version

mkdir ~/.pip
echo "[global]" > ~/.pip/pip.conf
echo "index-url = https://nexus.cloud.aws.tenablesecurity.com/repository/tenable_pypigroup/simple"       >> ~/.pip/pip.conf
echo "extra-index-url = https://nexus.cloud.aws.tenablesecurity.com/repository/tenable_pypigroup/simple" >> ~/.pip/pip.conf
echo "index = https://nexus.cloud.aws.tenablesecurity.com//tenable_pypigroup/pypi"                       >> ~/.pip/pip.conf

# https://github.com/pypa/twine/issues/1015
pip3 install -v "readme-renderer < 42.0" 
pip3 install pip setuptools twine pipdeptree -U

export PYTHONPATH=.
export PYTHONHASHSEED=0

echo "Produce the wheel"
python setup.py bdist_wheel

echo "Upload package to nexus"
python3 -m twine upload -r nexus dist/catium_nessus*.whl
