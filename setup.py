import os
import sys
from setuptools import setup, find_packages

# Version information
version='0.1.0'

# Read long description from README
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='truefa',
    version=version,
    description='A secure two-factor authentication code generator',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='TrueFA Team',
    author_email='example@truefa.com',
    url='https://github.com/zainibeats/truefa',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    package_data={
        'truefa_crypto': ['*.so', '*.dll'],
    },
    include_package_data=True,
    python_requires='>=3.8',
    install_requires=[
        'cryptography>=41.0.0',
        'pyzbar>=0.1.9',
        'pillow>=10.0.0',
        'pyotp>=2.8.0',
        'qrcode>=7.4.2',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Rust',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
    ],
    entry_points={
        'console_scripts': [
            'truefa=src.main:main',
        ],
    },
) 