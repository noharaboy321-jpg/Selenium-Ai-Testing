"""
:copyright: Tenable Network Security, 2019
:date: February 27th, 2019
:last_modified: July 01, 2020
:author: @pellsworth, @yshah, @kpanchal
"""

from typing import List

import requests

from catium.lib.activation_code_generator.activation_code_generator import ActivationCodeGenerator
from catium.lib.const.base_constants import TIME_TEN_SECONDS
from catium.lib.errors import CatiumActivationCodeGeneratorError
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.cli_command import execute, created_pexpect
from nessus.helpers.nessuscli.fetch import register
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.tests.api.server.conftest import _reload_nessus


def update(_args: List = []) -> dict:
    args = ['update'] + _args

    return execute(command=get_nessus_cli(), args=args)


def activation_code_generator(expire_days: int, product_type: str, flag: bool = False) -> None:
    """
    Generates the activation code and update the code in the product.
    :param int expire_days: Number of days
    :param str product_type: type of product
    :param bool flag: to return activation code
    :return: None
    """
    response = None
    api = NessusAPI()
    post_data = {'expiredays': expire_days, 'type': product_type}

    try:
        response = requests.post(ActivationCodeGenerator.url, data=post_data, timeout=TIME_TEN_SECONDS)
        license_code = response.json()['code']

        if flag:
            return license_code

        register(serial=license_code)
        _reload_nessus(api)
    except:
        raise CatiumActivationCodeGeneratorError('Error. HTTP {0} status code returned.'.format(response.status_code))


def reset_nessus_license() -> dict:
    """ This CLI helper function helps to reset Nessus license """
    au = created_pexpect(get_nessus_cli(), ['fix', '--reset'])

    try:
        au.expect('\(y/n\) \[n\]:')
        au.sendline('y')
        au.expect('y')
        data = au.read()
        au.close()
        return {'rc': au.status, 'stdout': data.decode('utf-8'), 'stderr': ''}
    except:
        au.close()
        return {'rc': au.status, 'stdout': au.before.decode('utf-8'), 'stderr': ''}
