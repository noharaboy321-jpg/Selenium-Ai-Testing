import re
import subprocess

import setuptools

RE_VERSION = re.compile(r'__version__\s*=\s*[\'\"]([\w.\-+]+)[\'\"]')


def read_requirements():
    """parses requirements from requirements.txt"""
    with open('requirements.txt') as f:
        requirements = [line for line in f.read().splitlines() if line.strip() and not line.strip().startswith('#')]
        return requirements


def get_version():
    """catium-core version from __init__.py"""
    with open('nessus/__init__.py') as fp:
        version = RE_VERSION.findall(fp.read())[0].strip()
        return version


def get_git_url() -> str:
    sp = subprocess.run(['git', 'config', '--get', 'remote.origin.url'], stdout=subprocess.PIPE)
    return sp.stdout.decode('ASCII').strip()


def main():
    with open("README.md", "r") as fh:
        long_description = fh.read()

    setuptools.setup(
        name='catium-nessus',
        version=get_version(),
        author='Test Automation Infrastructure Team',
        author_email='automation@tenable.com',
        description='Framework component for nessus test automation',
        long_description=long_description,
        long_description_content_type="text/markdown",
        url=get_git_url(),
        packages=setuptools.find_packages(include=('nessus*',), exclude=('nessus.tests*',)),
        include_package_data=True,
        install_requires=read_requirements(),
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: Other/Proprietary License",
            "Operating System :: OS Independent",
        ]
    )


if __name__ == '__main__':
    main()
