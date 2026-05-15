#!/usr/bin/env bash

echo ""
echo " # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # "
echo ""
echo "setup.sh has been deprecated. Please use"
echo ""
echo "      python3 autosetup.py"
echo ""
echo "instead. To see available options:"
echo "https://confluence.corp.tenablesecurity.com/pages/editpage.action?pageId=54638420"
echo "or python3 autosetup.py --help"
echo ""
echo " # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # "
echo ""
echo "Waiting 10 seconds before running python3 autosetup.py ${@}"
echo ""

sleep 10
python3 autosetup.py ${@}
