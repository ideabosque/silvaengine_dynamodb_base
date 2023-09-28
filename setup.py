#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = "bibow"

from setuptools import find_packages, setup

setup(
    name="SilvaEngine-DynamoDB-Base",
    version="0.0.1",
    author="Idea Bosque",
    author_email="ideabosque@gmail.com",
    description="SilvaEngine DynamoDB Base",
    long_description=__doc__,
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    platforms="Linux",
    install_requires=["SilvaEngine-Utility", "tenacity", "pynamodb", "deepdiff"],
    classifiers=[
        "Programming Language :: Python",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
