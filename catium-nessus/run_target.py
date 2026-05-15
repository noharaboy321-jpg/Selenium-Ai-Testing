"""
:copyright: Tenable Network Security, 2017
:date: November 12, 2017
:author: @lestevez
"""

from json import load
from time import sleep
from subprocess import call
from datetime import datetime

CMD = "CAT_URL=https://{URL} python -m pytest nessus/tests/ui/scans/test_scans_on_controller.py"
DATE = datetime.now().strftime('%y-%m-%d-%H:%M:%S')

num = 0

with open('servers.json', "r") as data_file:
    data = load(data_file)

servers = list(data['servers'])

for server in servers:
    num = num + 1

    run_cmd = CMD.format(URL=server)
    file_name = "{date}-{server}.txt".format(date=DATE, server=server)

    file_stream = open(file_name, "w")

    code = call(run_cmd, stdout=file_stream, shell=True)
    
    file_stream.close()

    print("Test Num # {} -- Exit Code: {} -- file: {}".format(num, code, file_name))

    sleep(5)