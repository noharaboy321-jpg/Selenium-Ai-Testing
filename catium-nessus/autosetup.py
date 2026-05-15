import sys
import types
from urllib.request import urlopen

MODULE_URL = 'http://internal-tf-automation-autoweb-lb-864108751.us-east-1.elb.amazonaws.com/catium/autosetup.py'


def load_module(module_url) -> object:
    """
    Load module from URL
    :param module_url:
    :return:
    """
    name = 'autoconfig'
    mod = types.ModuleType(name)
    mod.__file__ = module_url
    mod.__package__ = name.split('.')[0]

    sys.modules[name] = mod
    exec(urlopen(module_url).read(), mod.__dict__)
    return mod


if __name__ == '__main__':
    autoconfig = load_module(MODULE_URL)
    autosetup = autoconfig.SetupAutomation()  # pylint: disable=no-member
    autosetup.setup()
