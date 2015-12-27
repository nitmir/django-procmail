#!/usr/bin/env python
import os
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-procmail',
    version='0.1',
    packages=[
        'procmail', 'procmail.migrations',
    ],
    include_package_data=True,
    license='GPLv3',
    description=(
        "A web interface for editing procmail's procmailrc files."
    ),
    long_description=README,
    author='Valentin Samir',
    author_email='valentin.samir@crans.org',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
    package_data={
        'procmail': [
            'templates/procmail/*',
            'static/procmail/*',
            'locale/*/LC_MESSAGES/*',
        ]
    },
    keywords=['django', 'procmail', 'mail', 'filter', 'gui', 'web', 'interface'],
    install_requires=[
        'Django >= 1.7,<1.10', 'pyprocmail', 'chardet', "django-formtools"
    ],
    url="https://github.com/nitmir/django-procmail",
    download_url="https://github.com/nitmir/django-procmail/releases",
    zip_safe=False
)
