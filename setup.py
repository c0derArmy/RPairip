#!/usr/bin/env python3
import os
from setuptools import setup, find_packages

setup(
    name='RPairip',
    version='1.0.0',
    description='Automated PairIP protection removal tool for Android APKs',
    author='c0derArm',
    packages=find_packages() + [''],
    package_dir={'': '.'},
    py_modules=['pairip_autopatcher'],
    install_requires=[],
    entry_points={
        'console_scripts': [
            'RPairip=pairip_autopatcher:main',
        ],
    },
    python_requires='>=3.8',
)
