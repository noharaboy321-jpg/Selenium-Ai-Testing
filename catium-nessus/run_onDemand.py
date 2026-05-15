#!/usr/bin/env python3
"""
This script can be used to run tests on-demand against targets. The user will be prompted
for the needful and use the necessary environmental variables.

Setup needed:
python3, run autoconfig.py and pip3 install -r requirements.txt
"""

import os
import subprocess
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--host", dest="nessus_host",
    type=str, help="specify Nessus host")
parser.add_argument("--port", dest="nessus_port",
    type=int, help="specify port")
parser.add_argument("--ssh", dest="ssh_local",
    type=int, help="SSH local or remote (0 or 1)")
parser.add_argument("--ssh_port", dest="nessus_ssh_port",
    type=int, help="SSH local or remote")
parser.add_argument("--ssh_user", dest="nessus_ssh_user",
    type=str, help="specify ssh username")
parser.add_argument("--ssh_pass", dest="nessus_ssh_passwd",
    type=str, help="specify ssh passwd")
parser.add_argument("--tests", dest="tests_to_run",
    type=str, help="specify tests to run (i.e. nessus/tests/api, nessus/tests/ui -k test_feed_status)")
parser.add_argument("--license", dest="license_type",
    type=str, help="specify Nessus license type")
parser.add_argument("--platform", dest="platform",
    type=str, help="specify platform these tests are running against")
parser.add_argument("--ignore", dest="tests_to_ignore",
    type=str, help="specify tests to ignore")
parser.add_argument("--reruns", dest="test_reruns",
    type=int, help="specify number of rerun attempts")
parser.add_argument("--log_level", dest="log_level",
    type=str, help="specify pytest log level (info, debug)")

args = parser.parse_args()

if not args.nessus_host:
    args.nessus_host = input("IP of Nessus target to use: ")
if not args.nessus_port:
    args.nessus_port = input("Port of Nessus target to use: ")
if not args.ssh_local and args.ssh_local != 0:
    args.ssh_local = input("SSH local or remote: ")
if args.ssh_local == 0 or args.ssh_local == "remote":
    if not args.nessus_ssh_port:
        args.nessus_ssh_port = input("SSH remote port: ")
    if not args.nessus_ssh_user:
        args.nessus_ssh_user = input("SSH username: ")
    if not args.nessus_ssh_passwd:
        args.nessus_ssh_passwd = input("SSH password: ")
    os.environ['CAT_NESSUS_CLI_LOCAL'] = str(0)
else:
    os.environ['CAT_NESSUS_CLI_LOCAL'] = str(1)

CAT_URL='https://'+args.nessus_host + ':' + str(args.nessus_port)

if not args.tests_to_run:
    args.tests_to_run = input("Tests to run (i.e. nessus/tests/api, nessus/tests/ui -k test_feed_status): ")
if not args.license_type:
    args.license_type = input("What Nessus license type (pro, manager, essentials): ")
if not args.platform:
    args.platform = input("What platform are these tests running against (linux, windows, mac, freebsd): ")

if args.license_type == "essentials":
    args.license_type = "home"

if 'nessus/tests/ui' in args.tests_to_run:
    os.environ['CAT_USE_GRID'] = str(True)
    test_markers = "nessus_" + args.license_type + " and not standalone and not update and not license_change and not advanced_settings and not scanning"
elif 'nessus/tests/api' in args.tests_to_run:
    test_markers = "nessus_" + args.license_type + " and not standalone and not update and not skip_pro_scan_api_disabled"
else:
    test_markers = "nessus_" + args.license_type + " and nessus_cli"

if not args.test_reruns and args.test_reruns != 0:
    args.test_reruns = input("How many rerun attempts: ")
test_reruns = "--reruns=" + str(args.test_reruns)
if not args.log_level:
    args.log_level = input("What level of logging (info, debug): ")

try:
    aws_access_id = os.environ['AWS_ACCESS_KEY_ID']
except KeyError:
    aws_access_id = input("Please provide a valid AWS_ACCESS_KEY_ID: ")

try:
    aws_access_key = os.environ['AWS_SECRET_ACCESS_KEY']
except KeyError:
    aws_access_key = input("Please provide a valid AWS_SECRET_ACCESS_KEY: ")

os.environ['CAT_NESSUS_PLATFORM'] = args.platform
os.environ['CAT_TIO_URL'] = 'qa-develop.cloud.aws.tenablesecurity.com'
os.environ['CAT_SSH_USERNAME'] = args.nessus_ssh_user
os.environ['CAT_SSH_PASSWORD'] = args.nessus_ssh_passwd
os.environ['CAT_URL'] = CAT_URL
os.environ['PYTHONPATH'] = '.'
os.environ['PLUGIN_SERVER'] = 'plugins-internal-prod.cloud.aws.tenablesecurity.com'
os.environ['CAT_SSH_PORT'] = str(args.nessus_ssh_port)
os.environ['CAT_LOG_LEVEL_CONSOLE'] = args.log_level
os.environ['AWS_ACCESS_KEY_ID'] = aws_access_id
os.environ['AWS_SECRET_ACCESS_KEY'] = aws_access_key
os.environ['bamboo_workaround'] = 'trigger.is_ci_environment.function'

cmd = ['py.test', '-m', test_markers, test_reruns]
if args.tests_to_ignore and args.tests_to_ignore != "None":
    tests_to_ignore = "--ignore=" + args.tests_to_ignore
    cmd.extend(tests_to_ignore)

cmd.extend(args.tests_to_run.split(' '))
subprocess.run(cmd)
