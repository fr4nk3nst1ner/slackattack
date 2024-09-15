import os
from setuptools import setup, find_packages

# Read long description from README.md
with open('README.md', 'r') as f:
    long_description = f.read()

# Read the requirements from requirements.txt
try:
    with open('requirements.txt', 'r') as f:
        requirements = f.read().splitlines() if os.path.exists('requirements.txt') else []
except FileNotFoundError:
    requirements = []

# Read the version from slackattack/_version.py
version = {}
with open(os.path.join('slackattack', '_version.py')) as f:  
    exec(f.read(), version)

setup(
    name='slackattack',
    version=version['__version__'],  
    author='Jonathan Stines',
    description='Slack post-exploitation script for leaked bot tokens and "d" cookies',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/fr4nk3nst1ner/slackattack',
    packages=find_packages(),  
    include_package_data=True,  
    install_requires=requirements,
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    entry_points={  
        'console_scripts': [
            'slackattack=slackattack.slackattack:main',  
        ],
    },
)
